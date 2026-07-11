#include "workspace_fixture_builder.hpp"

#include "../../src/core/analysis/workspace/search_index.hpp"
#include "../../src/core/analysis/workspace/patched_export.hpp"

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string_view>

namespace {

using namespace aida::analysis;
using namespace aida::analysis::test_fixture;

address_t fixture_address(const std::shared_ptr<analysis_workspace_t>& workspace,
                          std::uint64_t rva)
{
    address_t address;
    address.space = address_space_id_t::virtual_address;
    address.value = workspace->image()->image_base() + rva;
    address.architecture = workspace->identity().architecture();
    address.mode = workspace->image()->architecture_mode();
    return address;
}

overlay_operation_t operation(overlay_operation_kind_t kind,
                              const std::shared_ptr<analysis_workspace_t>& workspace,
                              std::uint64_t rva)
{
    overlay_operation_t value;
    value.kind = kind;
    value.address = fixture_address(workspace, rva);
    return value;
}

std::vector<overlay_operation_t> complete_operation_set(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    std::vector<overlay_operation_t> values;
    auto comment = operation(overlay_operation_kind_t::comment, workspace, 0x1000);
    comment.text = "workspace comment";
    values.push_back(std::move(comment));
    auto name = operation(overlay_operation_kind_t::name, workspace, 0x1000);
    name.name = "workspace_entry";
    values.push_back(std::move(name));
    auto bookmark = operation(overlay_operation_kind_t::bookmark, workspace, 0x1001);
    bookmark.name = "entry bookmark";
    values.push_back(std::move(bookmark));
    auto declaration = operation(overlay_operation_kind_t::type_declaration, workspace, 0);
    declaration.name = "AIDA_FIXTURE_T";
    declaration.type = "struct AIDA_FIXTURE_T { unsigned value; };";
    values.push_back(std::move(declaration));
    auto function = operation(overlay_operation_kind_t::define_function, workspace, 0x1000);
    function.end = fixture_address(workspace, 0x1006);
    values.push_back(std::move(function));
    auto code = operation(overlay_operation_kind_t::define_code, workspace, 0x1006);
    code.end = fixture_address(workspace, 0x1008);
    values.push_back(std::move(code));
    auto data = operation(overlay_operation_kind_t::define_data, workspace, 0x1040);
    data.end = fixture_address(workspace, 0x1048);
    data.type = "unsigned char[8]";
    values.push_back(std::move(data));
    auto undefine = operation(overlay_operation_kind_t::undefine, workspace, 0x1050);
    undefine.end = fixture_address(workspace, 0x1054);
    values.push_back(std::move(undefine));
    auto stack = operation(overlay_operation_kind_t::stack_variable, workspace, 0x1000);
    stack.name = "local_value";
    stack.type = "unsigned int";
    stack.stack_offset = -8;
    values.push_back(std::move(stack));
    auto application = operation(overlay_operation_kind_t::type_application, workspace, 0x1040);
    application.name = "fixture_global";
    application.variable = "fixture_global";
    application.type = "AIDA_FIXTURE_T";
    values.push_back(std::move(application));
    auto bytes = operation(overlay_operation_kind_t::byte_patch, workspace, 0x1010);
    bytes.bytes = {0xAA, 0xBB};
    values.push_back(std::move(bytes));
    auto assembly = operation(overlay_operation_kind_t::assembly_patch, workspace, 0x1020);
    assembly.bytes = {0x90};
    assembly.assembly = "nop";
    values.push_back(std::move(assembly));
    auto integer = operation(overlay_operation_kind_t::integer_patch, workspace, 0x1030);
    integer.bytes = {0x34, 0x12};
    integer.integer_type = "u16le";
    integer.integer_value = "4660";
    values.push_back(std::move(integer));
    return values;
}

void require_error(const workspace_result_t<overlay_transaction_result_t>& result,
                   workspace_error_code_t code, const char* message)
{
    if (result || result.error().code != code)
        throw fixture_error_t(message);
}

class source_contract_t final {
public:
    source_contract_t(const std::filesystem::path& root, const char* relative)
        : relative_(relative), path_(root / std::filesystem::path(relative))
    {
        std::ifstream stream(path_, std::ios::binary);
        if (!stream)
            throw fixture_error_t("source contract file is unavailable: " + relative_);
        std::ostringstream contents;
        contents << stream.rdbuf();
        if (stream.bad())
            throw fixture_error_t("source contract file could not be read: " + relative_);
        text_ = contents.str();
        if (text_.empty())
            throw fixture_error_t("source contract file is empty: " + relative_);
    }

    const std::string& text() const noexcept
    {
        return text_;
    }

    std::size_t require(std::string_view needle, const char* contract,
                        std::size_t start = 0) const
    {
        const auto position = text_.find(needle, start);
        if (position == std::string::npos)
            throw fixture_error_t(relative_ + ": missing source contract " + contract);
        return position;
    }

    void reject(std::string_view needle, const char* contract) const
    {
        if (text_.find(needle) != std::string::npos)
            throw fixture_error_t(relative_ + ": forbidden source contract " + contract);
    }

    std::string_view block_after(std::string_view marker, const char* contract) const
    {
        const auto marker_position = require(marker, contract);
        const auto open = text_.find('{', marker_position + marker.size());
        if (open == std::string::npos)
            throw fixture_error_t(relative_ + ": missing source block " + contract);
        const auto close = matching_delimiter(text_, open, '{', '}', relative_, contract);
        return std::string_view(text_).substr(open, close - open + 1);
    }

    std::string_view statement_after(std::string_view marker, const char* contract) const
    {
        const auto start = require(marker, contract);
        const auto end = text_.find(';', start + marker.size());
        if (end == std::string::npos)
            throw fixture_error_t(relative_ + ": missing source statement " + contract);
        return std::string_view(text_).substr(start, end - start + 1);
    }

    std::string_view range(std::string_view begin_marker, std::string_view end_marker,
                           const char* contract) const
    {
        const auto begin = require(begin_marker, contract);
        const auto end = require(end_marker, contract, begin + begin_marker.size());
        return std::string_view(text_).substr(begin, end - begin + end_marker.size());
    }

    static std::size_t matching_delimiter(std::string_view source, std::size_t start,
                                          char open, char close,
                                          const std::string& relative,
                                          const char* contract)
    {
        if (start >= source.size() || source[start] != open)
            throw fixture_error_t(relative + ": invalid source delimiter for " + contract);
        std::size_t depth = 0;
        char quote = 0;
        bool escaped = false;
        bool line_comment = false;
        bool block_comment = false;
        for (std::size_t index = start; index < source.size(); ++index) {
            const char character = source[index];
            const char next = index + 1 < source.size() ? source[index + 1] : 0;
            if (line_comment) {
                if (character == '\n') line_comment = false;
                continue;
            }
            if (block_comment) {
                if (character == '*' && next == '/') {
                    block_comment = false;
                    ++index;
                }
                continue;
            }
            if (quote != 0) {
                if (escaped) {
                    escaped = false;
                    continue;
                }
                if (character == '\\') {
                    escaped = true;
                    continue;
                }
                if (character == quote) quote = 0;
                continue;
            }
            if (character == '/' && next == '/') {
                line_comment = true;
                ++index;
                continue;
            }
            if (character == '/' && next == '*') {
                block_comment = true;
                ++index;
                continue;
            }
            if (character == '"' || character == '\'') {
                quote = character;
                continue;
            }
            if (character == open) {
                ++depth;
                continue;
            }
            if (character == close) {
                if (depth == 0)
                    throw fixture_error_t(relative + ": unbalanced source delimiter for " + contract);
                --depth;
                if (depth == 0) return index;
            }
        }
        throw fixture_error_t(relative + ": unterminated source delimiter for " + contract);
    }

private:
    std::string relative_;
    std::filesystem::path path_;
    std::string text_;
};

void require_contains(std::string_view scope, std::string_view needle,
                      const char* contract)
{
    if (scope.find(needle) == std::string_view::npos)
        throw fixture_error_t(std::string("missing source contract: ") + contract);
}

void reject_contains(std::string_view scope, std::string_view needle,
                     const char* contract)
{
    if (scope.find(needle) != std::string_view::npos)
        throw fixture_error_t(std::string("forbidden source contract: ") + contract);
}

void require_ordered(std::string_view scope,
                     std::initializer_list<std::string_view> needles,
                     const char* contract)
{
    std::size_t cursor = 0;
    for (const auto needle : needles) {
        const auto position = scope.find(needle, cursor);
        if (position == std::string_view::npos)
            throw fixture_error_t(std::string("missing or reordered source contract: ") + contract);
        cursor = position + needle.size();
    }
}

std::size_t occurrence_count(std::string_view scope, std::string_view needle)
{
    std::size_t count = 0;
    std::size_t cursor = 0;
    while ((cursor = scope.find(needle, cursor)) != std::string_view::npos) {
        ++count;
        cursor += needle.size();
    }
    return count;
}

std::filesystem::path locate_repository_root()
{
    std::array<std::filesystem::path, 2> seeds{
        std::filesystem::path(__FILE__).parent_path(),
        std::filesystem::current_path()
    };
    for (auto seed : seeds) {
        std::error_code error;
        auto current = std::filesystem::absolute(seed, error);
        if (error) continue;
        for (std::size_t depth = 0; depth != 12; ++depth) {
            if (std::filesystem::is_regular_file(
                    current / "src/standalone/src/main.cpp", error) && !error &&
                std::filesystem::is_regular_file(
                    current / "src/standalone/tests/analysis_workspace/workspace_persistence_harness.cpp",
                    error) && !error)
                return current;
            const auto parent = current.parent_path();
            if (parent.empty() || parent == current) break;
            current = parent;
        }
    }
    throw fixture_error_t("repository root is unavailable for source contract checks");
}

void verify_explicit_workspace_persistence(const std::filesystem::path& root)
{
    source_contract_t header(root,
        "src/standalone/src/core/session/analysis_session.hpp");
    source_contract_t source(root,
        "src/standalone/src/core/session/analysis_session.cpp");
    header.require("acquire_static_workspace(", "explicit static workspace acquisition API");
    header.require("const aida::analysis::cancellation_token_t& cancel = {}",
        "explicit acquisition cancellation token");
    header.require("std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;",
        "session-owned workspace lifetime");

    const auto reopen = source.block_after(
        "workspace_result_t<bool> reopen_persisted_analysis(",
        "persisted workspace reopen");
    require_ordered(reopen, {
        "database->load_snapshot(workspace->normalized_image(), workspace->image(), cancel)",
        "snapshot->generation != workspace->generation()",
        "database->load_search_products(",
        "search_index_t::build(snapshot",
        "if (cancel.stop_requested())",
        "workspace->publish_analysis_bundle(workspace->generation()"
    }, "persisted snapshot publication stays bound to the acquired workspace");
    require_contains(reopen, "snapshot->overlay_revision != workspace->overlay_revision()",
        "persisted overlay revision gate");

    const auto acquire = source.block_after(
        "acquire_static_workspace(const std::string& path,",
        "static workspace acquisition implementation");
    require_ordered(acquire, {
        "if (cancel.stop_requested())",
        "workspace_registry().open_static(request, cancel)",
        "static_workspace_gate(workspace->identity().binary_id().to_hex())",
        "install_workspace_services(workspace, database)",
        "reopen_persisted_analysis(workspace, database, cancel)",
        "baseline_analysis_service_t::start(workspace, settings,",
        "cancel.deadline()"
    }, "static workspace acquisition persistence and cancellation sequence");

    const auto worker = source.block_after(
        "void static_open_worker(std::string session_id, std::string path,",
        "static open worker");
    require_ordered(worker, {
        "acquire_static_workspace(path, cancel)",
        "bind_workspace(session_id, result.workspace",
        "!workspace_for_session_id(session_id) && !result.joined_existing",
        "result.workspace->request_cancel()",
        "workspace_registry().close(result.workspace->identity().binary_id()"
    }, "orphaned static workspace cancellation and close");

    const auto bind = source.block_after(
        "bool bind_workspace(const std::string& session_id,",
        "explicit workspace session binding");
    require_contains(bind, "workspace->identity().binary_id()",
        "session binding binary identity");
    require_contains(bind, "workspace_registry().select_for_ui(",
        "session binding registry selection");
}

void verify_session_lifetime_and_selection(const std::filesystem::path& root)
{
    source_contract_t header(root,
        "src/standalone/src/core/session/analysis_session.hpp");
    source_contract_t source(root,
        "src/standalone/src/core/session/analysis_session.cpp");
    header.require("aida::analysis::cancellation_source_t load_cancellation;",
        "session load cancellation source");
    header.require("std::optional<std::uint64_t> open_task_id;",
        "session open task ownership");
    header.require("std::optional<aida::infra::taskflow_runtime::job_handle_t> baseline_job;",
        "session baseline job ownership");
    header.require("std::shared_ptr<const analysis_session_t> session_handle_at(size_t idx);",
        "owned session snapshot API");

    const auto cancel = source.block_after("bool cancel_session(size_t idx)",
        "session cancellation");
    require_ordered(cancel, {
        "session.load_cancellation.request_cancel()",
        "session.open_task_id.reset()",
        "session.baseline_job.reset()",
        "aida::infra::executor::cancel(*open_task_id)",
        "aida::infra::taskflow_runtime::cancel(*baseline_job)",
        "workspace->request_cancel()"
    }, "session cancellation owns and cancels every asynchronous lifetime");

    const auto close = source.block_after("bool close_session(size_t idx)",
        "session close");
    require_ordered(close, {
        "session->load_cancellation.request_cancel()",
        "state().sessions.erase(",
        "aida::infra::executor::cancel(*open_task_id)",
        "aida::infra::taskflow_runtime::cancel(*baseline_job)",
        "close_workspace_async(std::move(workspace), pid, std::move(live_binding))",
        "activate_session_transaction(*successor_index"
    }, "session close cancellation and successor activation");

    const auto activation = source.block_after(
        "bool activate_session_transaction(size_t idx, std::string* out_error)",
        "transactional session activation");
    require_ordered(activation, {
        "std::lock_guard<std::recursive_mutex> activation_lock(state().activation_mutex)",
        "validate_live_session_binding(session->id, workspace, nullptr, error)",
        "ensure_driver_active_for_session(session->attached_pid",
        "validate_live_session_binding(session->id, workspace, nullptr, error)",
        "workspace_registry().select_for_ui(workspace->identity().binary_id())",
        "candidate->ui_selected = false",
        "session->ui_selected = true",
        "state().active_idx = static_cast<int>(idx)"
    }, "driver registry and UI session selection commit atomically");
    if (occurrence_count(activation, "rollback_driver_activation(") < 3)
        throw fixture_error_t("transactional session activation lacks fail-closed driver rollback");

    const auto switching = source.block_after("bool switch_session(size_t idx)",
        "public session switch");
    require_contains(switching, "return activate_session_transaction(idx, nullptr);",
        "public session switch delegates to transaction");
}

void verify_live_pid_identity(const std::filesystem::path& root)
{
    source_contract_t identity_header(root,
        "src/standalone/src/core/runtime/standalone_driver_identity.hpp");
    source_contract_t driver(root,
        "src/standalone/src/core/runtime/standalone_driver.cpp");
    source_contract_t registry(root,
        "src/standalone/src/core/analysis/workspace/workspace_registry.cpp");
    source_contract_t session(root,
        "src/standalone/src/core/session/analysis_session.cpp");

    identity_header.require("struct process_creation_identity_t",
        "process creation identity type");
    identity_header.require("std::uint64_t creation_time_100ns = 0;",
        "process creation timestamp identity");
    identity_header.require("process_identity_changed",
        "PID reuse staleness class");
    identity_header.require("module_identity_changed",
        "module replacement staleness class");
    identity_header.require("validate_live_target_identity(const live_target_identity_t& expected)",
        "live identity validation API");

    const auto capture = driver.block_after(
        "bool capture_identity_impl(std::uint32_t pid, std::uint64_t preferred_module_base,",
        "live process identity capture");
    require_ordered(capture, {
        "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE",
        "GetExitCodeProcess(process, &exit_code)",
        "GetProcessTimes(process, &creation, &exit, &kernel, &user)",
        "QueryFullProcessImageNameW(process",
        "CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32",
        "out.process.creation_time_100ns = filetime_to_u64(creation)",
        "out.module.base = selected->base",
        "out_staleness = staleness_t::none"
    }, "live identity captures process generation and module identity");

    const auto validate = driver.block_after(
        "validation_result_t validate_live_target_identity(const live_target_identity_t& expected)",
        "live identity staleness validation");
    require_ordered(validate, {
        "capture_identity_impl(expected.process.pid, expected.module.base",
        "result.observed.process.creation_time_100ns != expected.process.creation_time_100ns",
        "result.staleness = staleness_t::process_identity_changed",
        "result.observed.module.base != expected.module.base",
        "result.staleness = staleness_t::module_identity_changed",
        "result.matches = true"
    }, "PID reuse and module replacement fail stale");

    const auto find_pid = registry.block_after(
        "workspace_registry_t::find_by_pid(", "creation-bound PID lookup");
    require_contains(find_pid,
        "creation_time_100ns && process->creation_time_100ns != *creation_time_100ns",
        "PID lookup creation timestamp filter");
    const auto resolve = registry.block_after(
        "workspace_registry_t::resolve(", "creation-bound target resolution");
    require_ordered(resolve, {
        "selector.process_creation_time_100ns && !selector.pid",
        "process->creation_time_100ns != *selector.process_creation_time_100ns",
        "pid_exists_with_other_creation = true",
        "workspace_error_code_t::target_stale",
        "PID was reused by a different process identity"
    }, "PID selector rejects a reused process generation");

    const auto attach = session.block_after(
        "bool open_attach_session(std::uint32_t pid, std::string* out_err)",
        "live session creation");
    require_ordered(attach, {
        "capture_live_target_identity(pid, 0, source_identity",
        "ensure_driver_active_for_session(pid",
        "request.snapshot.pid = pid",
        "workspace_registry().open_live(request)",
        "make_live_session_binding(source_identity, workspace",
        "validate_live_target_identity(source_identity)",
        "provider->validate_current_identity()",
        "activate_session_transaction(session_index"
    }, "live session creation validates immutable identity before publication");
    require_contains(attach, "binding.source_identity.process.creation_time_100ns",
        "live session creation-time evidence");
}

std::size_t top_level_argument_count(std::string_view arguments)
{
    std::size_t count = 0;
    std::size_t start = 0;
    std::size_t round = 0;
    std::size_t square = 0;
    std::size_t curly = 0;
    char quote = 0;
    bool escaped = false;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const char character = arguments[index];
        if (quote != 0) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (character == '\\') {
                escaped = true;
                continue;
            }
            if (character == quote) quote = 0;
            continue;
        }
        if (character == '"' || character == '\'') {
            quote = character;
            continue;
        }
        if (character == '(') ++round;
        else if (character == ')') {
            if (round != 0) --round;
        } else if (character == '[') ++square;
        else if (character == ']') {
            if (square != 0) --square;
        } else if (character == '{') ++curly;
        else if (character == '}') {
            if (curly != 0) --curly;
        } else if (character == ',' && round == 0 && square == 0 && curly == 0) {
            if (arguments.substr(start, index - start).find_first_not_of(" \t\r\n") !=
                std::string_view::npos)
                ++count;
            start = index + 1;
        }
    }
    if (arguments.substr(start).find_first_not_of(" \t\r\n") != std::string_view::npos)
        ++count;
    return count;
}

void verify_hex_context_calls(const std::filesystem::path& root)
{
    struct call_contract_t {
        const char* name;
        std::size_t arguments;
        std::size_t occurrences = 0;
    };
    std::array<call_contract_t, 7> contracts{{
        {"activate", 1},
        {"read_live_memory", 3},
        {"close", 1},
        {"active", 1},
        {"source_name", 1},
        {"render", 9},
        {"last_error", 1}
    }};
    const auto source_root = root / "src/standalone/src";
    std::error_code error;
    for (std::filesystem::recursive_directory_iterator iterator(
             source_root, std::filesystem::directory_options::skip_permission_denied, error), end;
         iterator != end; iterator.increment(error)) {
        if (error) {
            error.clear();
            continue;
        }
        if (!iterator->is_regular_file(error) || error) {
            error.clear();
            continue;
        }
        const auto extension = iterator->path().extension().string();
        if (extension != ".cpp" && extension != ".hpp" && extension != ".h")
            continue;
        std::ifstream stream(iterator->path(), std::ios::binary);
        if (!stream)
            throw fixture_error_t("hex context callsite source is unavailable");
        std::ostringstream contents;
        contents << stream.rdbuf();
        const std::string source = contents.str();
        for (auto& contract : contracts) {
            const std::string marker = std::string("hex_view::") + contract.name + "(";
            std::size_t cursor = 0;
            while ((cursor = source.find(marker, cursor)) != std::string::npos) {
                const auto open = cursor + marker.size() - 1;
                const auto close = source_contract_t::matching_delimiter(
                    source, open, '(', ')', iterator->path().generic_string(), contract.name);
                const auto argument_count = top_level_argument_count(
                    std::string_view(source).substr(open + 1, close - open - 1));
                if (argument_count != contract.arguments) {
                    throw fixture_error_t(iterator->path().generic_string() +
                        ": hex context call has legacy argument shape: " + contract.name);
                }
                ++contract.occurrences;
                cursor = close + 1;
            }
        }
    }
    for (const auto& contract : contracts) {
        if (contract.occurrences == 0)
            throw fixture_error_t(std::string("hex context API has no production callsites: ") +
                contract.name);
    }
}

void verify_hex_context_fallback(const std::filesystem::path& root)
{
    source_contract_t header(root,
        "src/standalone/src/core/editor/hex_view.hpp");
    source_contract_t source(root,
        "src/standalone/src/core/editor/hex_view.cpp");
    source_contract_t browser(root,
        "src/standalone/src/helpers/file_browser.cpp");

    for (const auto signature : {
        "void activate(const disasm_view::workspace_context_t& context);",
        "bool read_live_memory(const disasm_view::workspace_context_t& context,",
        "void close(const disasm_view::workspace_context_t& context);",
        "bool active(const disasm_view::workspace_context_t& context);",
        "std::string source_name(const disasm_view::workspace_context_t& context);",
        "std::string last_error(const disasm_view::workspace_context_t& context);"
    })
        header.require(signature, "explicit hex workspace context API");
    header.reject("void activate();", "legacy global hex activation");
    header.reject("bool active();", "legacy global hex active state");
    header.reject("void close();", "legacy global hex close");

    source.reject("analysis_session::active_workspace()",
        "hex view global active workspace lookup");
    source.require("workspace_hex_state_t final : aida::analysis::workspace_lifecycle_participant_t",
        "workspace-bound hex lifecycle participant");
    const auto state = source.block_after(
        "std::shared_ptr<workspace_hex_state_t> state_for(",
        "workspace-bound hex state lookup");
    require_ordered(state, {
        "context.workspace->identity().binary_id()",
        "created->owner = context.workspace",
        "values.emplace(id, created)",
        "context.workspace->register_lifecycle_participant(created)"
    }, "hex state ownership follows explicit workspace identity");
    const auto cancellation = source.block_after(
        "void workspace_hex_state_t::request_cancel() noexcept",
        "hex workspace cancellation");
    require_ordered(cancellation, {
        "cancelled.store(true",
        "search->request_cancel()",
        "taskflow_runtime::cancel(patch)",
        "taskflow_runtime::cancel(search_task)",
        "unregister_state(owner_id, this)"
    }, "hex workspace cancellation drains owned work");

    const auto fallback = browser.block_after(
        "void async_hex_fallback(const std::string& path, bool archive)",
        "hex provider fallback");
    require_ordered(fallback, {
        "workspace_registry_t::cancel_admission(*previous)",
        "mapped_file_provider_t::open(path)",
        "open_archive_member_provider(provider, member",
        "open_provider_workspace_request_t request",
        "request.provider = provider",
        "workspace_registry().admit_verified_provider_async("
    }, "hex fallback admits a verified provider with cancellation");
    const auto completion = browser.block_after(
        "void complete_hex_preview_success(", "hex fallback completion");
    require_ordered(completion, {
        "workspace_registry().select_for_ui(",
        "disasm_view::capture_workspace(workspace)",
        "hex_view::activate(context)",
        "active_center_view = center_view_t::hex_view"
    }, "hex fallback publishes only an explicit captured workspace context");
    verify_hex_context_calls(root);
}

void verify_message_pump_invariants(const std::filesystem::path& root)
{
    source_contract_t main_source(root, "src/standalone/src/main.cpp");
    const auto queued_flags = main_source.statement_after(
        "static constexpr UINT kAidaQueuedPeekFlags", "queued message flags");
    for (const auto flag : {"PM_REMOVE", "PM_QS_INPUT", "PM_QS_POSTMESSAGE",
                            "PM_QS_PAINT", "PM_QS_SENDMESSAGE"})
        require_contains(queued_flags, flag, "queued message flag invariant");
    reject_contains(queued_flags, "PM_NOREMOVE", "queued message removal regression");

    const auto send_flags = main_source.statement_after(
        "static constexpr UINT kAidaSendOnlyPeekFlags", "send-only message flags");
    require_contains(send_flags, "PM_REMOVE | PM_QS_SENDMESSAGE",
        "send-only drain removes synchronous sends");
    reject_contains(send_flags, "PM_NOREMOVE", "send-only nonremoving probe");

    const auto pump = main_source.range(
        "aida_tracer::mark_render_phase(\"peek_message_probe\")",
        "aida_tracer::g_peek_return_count.fetch_add(1, std::memory_order_acq_rel)",
        "primary Win32 message pump");
    require_ordered(pump, {
        "GetQueueStatus(QS_ALLINPUT)",
        "if (queue_current == 0)",
        "send_message_pending",
        "if (send_only_pending)",
        "PeekMessage(&sent_probe, nullptr, 0U, 0U, kAidaSendOnlyPeekFlags)",
        "const UINT peek_remove_flags = kAidaQueuedPeekFlags",
        "PeekMessage(&msg, peek_filter, 0U, 0U, peek_remove_flags)"
    }, "primary message pump send and empty-queue probe sequence");
    const auto empty_queue = main_source.block_after(
        "if (queue_current == 0)", "empty-queue nonblocking probe path");
    reject_contains(empty_queue, "break;", "empty queue exits before PeekMessage probe");
    reject_contains(empty_queue, "continue;", "empty queue skips PeekMessage probe");
    reject_contains(empty_queue, "return", "empty queue returns before PeekMessage probe");

    const auto invariant_mask = main_source.block_after(
        "static uint64_t phase0_message_pump_invariant_mask()",
        "message pump runtime invariant mask");
    require_ordered(invariant_mask, {
        "kAidaQueuedPeekFlags & PM_QS_SENDMESSAGE",
        "kAidaQueuedPeekFlags & PM_REMOVE",
        "kAidaSendOnlyPeekFlags == (PM_REMOVE | PM_QS_SENDMESSAGE)",
        "kAidaNonSendQueueBits & QS_SENDMESSAGE",
        "kAidaPumpQueueBits & QS_SENDMESSAGE"
    }, "message pump runtime invariant self-check");
}

void verify_legacy_source_contracts()
{
    const auto root = locate_repository_root();
    verify_explicit_workspace_persistence(root);
    verify_session_lifetime_and_selection(root);
    verify_live_pid_identity(root);
    verify_hex_context_fallback(root);
    verify_message_pump_invariants(root);
}

}

int main()
{
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    std::shared_ptr<aida::analysis::analysis_workspace_t> reopened;
    std::string database_path;
    try {
        verify_legacy_source_contracts();
        fixture_root_t root("persistence");
        const auto path = write_fixture(root.path(), "one", "persist.exe", 41);
        workspace = open_workspace(path, "persist.exe");
        install_services(workspace);
        analyze_workspace(workspace, 1);
        database_path = workspace->database()->path();
        auto original_hash = sha256_provider(workspace->provider());
        if (!original_hash)
            throw fixture_error_t(original_hash.error().stable_code() + ":" + original_hash.error().message);

        overlay_transaction_request_t dry_request;
        dry_request.dry_run = true;
        dry_request.expected_revision = workspace->overlay_revision();
        dry_request.operations = complete_operation_set(workspace);
        auto dry = workspace->overlay()->transact(dry_request);
        if (!dry || dry.value().committed || !dry.value().dry_run ||
            dry.value().operations.size() != dry_request.operations.size() ||
            workspace->overlay_revision() != 0 || !workspace->overlay()->snapshot().items.empty())
            throw fixture_error_t("complete overlay dry run changed durable state");

        overlay_transaction_request_t commit_request;
        commit_request.expected_revision = 0;
        commit_request.idempotency_key = "persistence-harness-complete-set";
        commit_request.operations = complete_operation_set(workspace);
        auto committed = workspace->overlay()->transact(commit_request);
        if (!committed || !committed.value().committed || committed.value().revision != 1 ||
            committed.value().operations.size() != commit_request.operations.size())
            throw fixture_error_t("complete overlay commit did not publish revision one");
        auto replay = workspace->overlay()->transact(commit_request);
        if (!replay || !replay.value().idempotent_replay ||
            replay.value().transaction_id != committed.value().transaction_id)
            throw fixture_error_t("overlay idempotency replay changed transaction identity");

        overlay_transaction_request_t conflict_request;
        conflict_request.expected_revision = 0;
        conflict_request.operations.push_back(operation(
            overlay_operation_kind_t::comment, workspace, 0x1000));
        conflict_request.operations.front().text = "stale";
        require_error(workspace->overlay()->transact(conflict_request),
            workspace_error_code_t::revision_conflict,
            "stale expected revision did not fail closed");

        overlay_transaction_request_t malformed;
        malformed.operations.push_back(operation(overlay_operation_kind_t::comment, workspace, 0x1000));
        malformed.operations.front().text.assign((256u << 10) + 1, 'X');
        require_error(workspace->overlay()->transact(malformed), workspace_error_code_t::limit_exceeded,
            "oversized comment did not fail closed");
        malformed.operations.clear();
        malformed.operations.push_back(operation(overlay_operation_kind_t::define_code, workspace, 0x1010));
        malformed.operations.front().end = fixture_address(workspace, 0x100F);
        require_error(workspace->overlay()->transact(malformed), workspace_error_code_t::invalid_argument,
            "decreasing definition range did not fail closed");
        malformed.operations.clear();
        malformed.operations.push_back(operation(overlay_operation_kind_t::name, workspace, 0x3000));
        malformed.operations.front().name = "outside_image";
        auto outside = workspace->overlay()->transact(malformed);
        if (outside || outside.error().code != workspace_error_code_t::out_of_range)
            throw fixture_error_t("out-of-workspace overlay address did not fail closed");
        malformed.operations.clear();
        auto overlap_first = operation(overlay_operation_kind_t::byte_patch, workspace, 0x1060);
        overlap_first.bytes = {1, 2, 3};
        auto overlap_second = operation(overlay_operation_kind_t::assembly_patch, workspace, 0x1062);
        overlap_second.bytes = {0x90};
        overlap_second.assembly = "nop";
        malformed.operations = {overlap_first, overlap_second};
        require_error(workspace->overlay()->transact(malformed), workspace_error_code_t::revision_conflict,
            "overlapping patch transaction did not fail closed");

        auto undone = workspace->overlay()->undo(workspace->overlay_revision());
        if (!undone || !undone.value().committed || !workspace->overlay()->snapshot().items.empty())
            throw fixture_error_t("complete overlay undo failed");
        auto redone = workspace->overlay()->redo(workspace->overlay_revision());
        if (!redone || !redone.value().committed ||
            workspace->overlay()->snapshot().items.size() != commit_request.operations.size())
            throw fixture_error_t("complete overlay redo failed");

        overlay_transaction_request_t delete_stack;
        delete_stack.expected_revision = workspace->overlay_revision();
        auto remove_stack = operation(overlay_operation_kind_t::delete_stack_variable, workspace, 0x1000);
        remove_stack.name = "local_value";
        remove_stack.stack_offset = -8;
        delete_stack.operations.push_back(std::move(remove_stack));
        auto deleted = workspace->overlay()->transact(delete_stack);
        if (!deleted || !deleted.value().committed)
            throw fixture_error_t("stack variable deletion did not commit");

        const auto destination = root.path() / "patched" / "persist_patched.exe";
        std::filesystem::create_directories(destination.parent_path());
        auto exported = patched_export_t::export_copy(workspace, destination.u8string());
        if (!exported || exported.value().bytes_written != workspace->provider().size() ||
            exported.value().patched_bytes != 5 || exported.value().patch_records != 3 ||
            exported.value().overlay_revision != workspace->overlay_revision() ||
            exported.value().output_hash == original_hash.value())
            throw fixture_error_t("patched-copy export did not apply the three overlay patch records");
        auto existing_export = patched_export_t::export_copy(workspace, destination.u8string());
        if (existing_export || existing_export.error().code != workspace_error_code_t::revision_conflict)
            throw fixture_error_t("patched export overwrite refusal did not fail closed");
        auto invalid_export = patched_export_t::export_copy(
            workspace, (root.path() / "missing" / "bad.exe").u8string());
        if (invalid_export || invalid_export.error().code != workspace_error_code_t::io_failure)
            throw fixture_error_t("patched export missing-directory failure was not deterministic");

        auto after_hash = sha256_provider(workspace->provider());
        if (!after_hash || after_hash.value() != original_hash.value())
            throw fixture_error_t("overlay/export changed immutable source bytes");
        const auto persisted_revision = workspace->overlay_revision();
        close_workspace(workspace);
        workspace.reset();

        reopened = open_workspace(path, "persist.exe");
        install_services(reopened);
        if (reopened->snapshot() || reopened->search_index() ||
            reopened->analysis_revision() != 0 || reopened->overlay_revision() != 0)
            throw fixture_error_t("warm reopen acquired a workspace with residual in-memory analysis state");
        const auto recovered = reopened->overlay()->snapshot();
        if (reopened->overlay_revision() != persisted_revision || recovered.items.empty())
            throw fixture_error_t("overlay journal did not recover after reopen");
        std::set<overlay_operation_kind_t> recovered_kinds;
        for (const auto& item : recovered.items) recovered_kinds.insert(item.second.kind);
        for (const auto kind : {overlay_operation_kind_t::comment, overlay_operation_kind_t::name,
             overlay_operation_kind_t::bookmark, overlay_operation_kind_t::type_declaration,
             overlay_operation_kind_t::define_function, overlay_operation_kind_t::define_code,
             overlay_operation_kind_t::define_data, overlay_operation_kind_t::undefine,
             overlay_operation_kind_t::delete_stack_variable, overlay_operation_kind_t::type_application,
             overlay_operation_kind_t::byte_patch, overlay_operation_kind_t::assembly_patch,
             overlay_operation_kind_t::integer_patch}) {
            if (recovered_kinds.count(kind) == 0)
                throw fixture_error_t("overlay recovery lost an operation family");
        }
        auto loaded = reopened->database()->load_snapshot(reopened->normalized_image(),
            reopened->image(), reopened->cancellation_token());
        if (!loaded || !loaded.value())
            throw fixture_error_t("persisted baseline snapshot did not reopen");
        auto persisted_snapshot = loaded.take_value();
        if (!persisted_snapshot->baseline_complete ||
            persisted_snapshot->overlay_revision != persisted_revision)
            throw fixture_error_t("persisted baseline snapshot revision or completeness diverged");
        auto products = reopened->database()->load_search_products(
            persisted_snapshot->generation, persisted_snapshot->analysis_revision,
            persisted_snapshot->overlay_revision, reopened->cancellation_token());
        if (!products)
            throw fixture_error_t(products.error().stable_code() + ":" + products.error().message);
        auto metrics = std::make_shared<analysis_metrics_t>(persisted_snapshot->generation);
        auto rebuilt_index = search_index_t::build(persisted_snapshot,
            std::move(products.value().data_candidates),
            std::move(products.value().switches),
            std::move(products.value().types), metrics, {},
            reopened->cancellation_token());
        if (!rebuilt_index)
            throw fixture_error_t(rebuilt_index.error().stable_code() + ":" + rebuilt_index.error().message);
        auto published = reopened->publish_analysis_bundle(
            reopened->generation(), reopened->analysis_revision(),
            persisted_snapshot, rebuilt_index.take_value(), true);
        if (!published || reopened->progress().readiness != workspace_readiness_t::baseline_ready ||
            !reopened->snapshot() || !reopened->search_index())
            throw fixture_error_t("warm reopen did not publish the persisted snapshot and rebuilt search index");
        close_workspace(reopened, true);
        reopened.reset();
        std::cout << "workspace_persistence_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        try {
            if (reopened)
                close_workspace(reopened, true);
            else if (workspace)
                close_workspace(workspace, true);
            else
                remove_database_artifacts(database_path);
        } catch (...) {}
        std::cerr << error.what() << '\n';
        return 1;
    }
}
