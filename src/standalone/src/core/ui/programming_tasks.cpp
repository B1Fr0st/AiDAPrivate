#include "programming_tasks.hpp"

#include "application_view_registry.hpp"
#include "application_ui_runtime.hpp"
#include "design_system.hpp"
#include "task_center.hpp"
#include "ui_thread_dispatcher.hpp"
#include "../../preview/studio_semantics.hpp"
#include "../../helpers/globals.h"
#include "../infra/executor.hpp"
#include "../settings/standalone_settings.hpp"
#include "../settings/settings_persistence_service.hpp"

#include "imgui/imgui.h"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace aida::ui::programming_tasks {
namespace {

enum class configuration_kind_t : std::uint8_t { task, launch, test };
enum class configuration_origin_t : std::uint8_t { user, project };

std::filesystem::path path_from_utf8(std::string_view value) {
#if defined(__cpp_char8_t)
    const auto* begin = reinterpret_cast<const char8_t*>(value.data());
    return std::filesystem::path(std::u8string(begin, begin + value.size()));
#else
    return std::filesystem::u8path(value.begin(), value.end());
#endif
}

std::string path_to_utf8(const std::filesystem::path& value) {
    const auto encoded = value.generic_u8string();
#if defined(__cpp_char8_t)
    return std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size());
#else
    return encoded;
#endif
}

struct configuration_t {
    std::string id;
    std::string source_id;
    std::string name;
    std::string command;
    std::string cwd;
    std::string output_channel;
    std::string problem_matcher;
    configuration_kind_t kind = configuration_kind_t::task;
    configuration_origin_t origin = configuration_origin_t::user;
};

struct resolved_configuration_t {
    configuration_t source;
    std::string command;
    std::string cwd;
    std::string channel;
};

struct problem_t {
    std::string path;
    std::string severity;
    std::string message;
    int line = 0;
    int column = 0;
};

struct run_state_t {
    std::string id;
    resolved_configuration_t configuration;
    std::uint64_t generation = 0;
    std::atomic<bool> cancellation_requested{false};
    std::atomic<bool> terminal{false};
    std::atomic<std::uint32_t> problem_count{0};
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    std::mutex process_mutex;
    HANDLE job = INVALID_HANDLE_VALUE;
    HANDLE process = INVALID_HANDLE_VALUE;
    HANDLE output_read = INVALID_HANDLE_VALUE;
#endif
};

struct editor_state_t {
    int selected = -1;
    bool loaded = false;
    std::array<char, 128> name{};
    std::array<char, 8192> command{};
    std::array<char, 1024> cwd{};
    std::array<char, 128> channel{};
    int kind = 0;
    int matcher = 0;
    bool delete_requested = false;
    bool dirty = false;
    bool save_in_flight = false;
    bool clear_dirty_on_commit = false;
    std::uint64_t settings_generation = 0;
    std::string persistence_payload;
    std::string validation_error;
};

struct script_run_identity_t {
    std::string id;
    std::string source;
    std::string owner;
    std::string label;
    std::uint64_t queued_ms = 0;
    std::uint64_t snapshot_generation = 0;
};

struct state_t {
    std::vector<configuration_t> configurations;
    std::string project_root;
    std::string configuration_error;
    std::string script_action_error;
    std::string selected_id;
    std::vector<std::string> channels;
    std::string selected_channel;
    std::unordered_map<std::string, std::uint64_t> generations;
    std::unordered_map<std::string, std::shared_ptr<run_state_t>> active_runs;
    std::shared_ptr<run_state_t> last_run;
    std::atomic<std::size_t> active_count{0};
    std::atomic<std::size_t> retained_problem_count{0};
    std::atomic<std::uint64_t> configuration_generation{0};
    std::atomic<std::uint64_t> configuration_dispatch_failure_generation{0};
    std::optional<resolved_configuration_t> pending_run;
    std::optional<script_run_identity_t> selected_script_run;
    std::array<char, 128> scripts_filter{};
    bool initialized = false;
    bool configuration_loading = false;
    bool configure_open = false;
    bool run_review_open = false;
    editor_state_t editor;
    std::uint64_t next_run = 1;
    std::uint64_t next_configuration = 1;
    std::mutex mutex;
};

state_t& state() {
    static state_t value;
    return value;
}

void ensure_initialized();
const configuration_t* selected_configuration();

std::uint64_t now_ms() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    return static_cast<std::uint64_t>(ImGui::GetTime() * 1000.0);
#else
    return static_cast<std::uint64_t>(GetTickCount64());
#endif
}

std::string bounded(std::string value, std::size_t maximum) {
    if (value.size() > maximum) value.resize(maximum);
    return value;
}

std::string trim(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    }).base();
    return first < last ? std::string(first, last) : std::string{};
}

bool safe_identifier(const std::string& value) {
    if (value.empty() || value.size() > 96) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isalnum(ch) != 0 || ch == '.' || ch == '_' || ch == '-';
    });
}

bool control_free(std::string_view value) {
    return std::none_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch < 32 || ch == 127;
    });
}

std::string replace_all(std::string value, std::string_view token, std::string_view replacement) {
    std::size_t offset = 0;
    while ((offset = value.find(token, offset)) != std::string::npos) {
        value.replace(offset, token.size(), replacement);
        offset += replacement.size();
    }
    return value;
}

std::string file_directory(const std::string& path) {
	if (path.empty()) return {};
	return path_to_utf8(path_from_utf8(path).parent_path());
}

std::string expand_variables(std::string value, const std::string& explicit_file = {}) {
    const std::string file = explicit_file.empty()
        ? code_editor_widget::document_state().filepath : explicit_file;
    value = replace_all(std::move(value), "${workspaceFolder}", file_browser::current_dir);
    value = replace_all(std::move(value), "${file}", file);
    value = replace_all(std::move(value), "${fileDirname}", file_directory(file));
    return value;
}

std::string matcher_name(int index) {
    switch (index) {
    case 1: return "msvc";
    case 2: return "gcc";
    case 3: return "generic";
    default: return "none";
    }
}

int matcher_index(const std::string& value) {
    if (value == "msvc") return 1;
    if (value == "gcc") return 2;
    if (value == "generic") return 3;
    return 0;
}

std::string kind_name(configuration_kind_t value) {
    switch (value) {
    case configuration_kind_t::launch: return "launch";
    case configuration_kind_t::test: return "test";
    case configuration_kind_t::task: return "task";
    }
    return "task";
}

std::optional<resolved_configuration_t> resolve_configuration(const configuration_t& config,
                                                               std::string& error,
                                                               const std::string& explicit_file = {}) {
    resolved_configuration_t result;
    result.source = config;
    result.command = trim(expand_variables(config.command, explicit_file));
    result.cwd = trim(expand_variables(config.cwd, explicit_file));
    result.channel = trim(config.output_channel);
    if (result.channel.empty()) result.channel = config.name;
    result.channel = bounded(result.channel, 96);
    if (result.command.empty()) {
        error = "The selected configuration has no command";
        return std::nullopt;
    }
    if (result.command.find("${") != std::string::npos || result.cwd.find("${") != std::string::npos) {
        error = "The configuration contains a variable that cannot be resolved in the current workspace";
        return std::nullopt;
    }
    if (result.command.size() > 8192) {
        error = "The resolved command exceeds 8192 bytes";
        return std::nullopt;
    }
    if (result.cwd.size() > 1024) {
        error = "The resolved working directory exceeds 1024 bytes";
        return std::nullopt;
    }
    if (!result.cwd.empty()) {
        std::filesystem::path cwd_path(result.cwd);
        if (cwd_path.is_relative() && !file_browser::current_dir.empty())
            cwd_path = std::filesystem::path(file_browser::current_dir) / cwd_path;
        result.cwd = cwd_path.lexically_normal().string();
        if (result.cwd.size() > 1024) {
            error = "The resolved working directory exceeds 1024 bytes";
            return std::nullopt;
        }
    }
    if (result.channel.empty()) {
        error = "The selected configuration has no output channel";
        return std::nullopt;
    }
    error.clear();
    return result;
}

std::string file_run_unavailable_reason(const std::string& path,
        configuration_kind_t required) {
    ensure_initialized();
    if (path.empty()) return "Select a file in Project Explorer first";
    if (path.size() > 32768 || !control_free(path))
        return "The selected file path is not a valid bounded programming target";
    try {
        if (path_from_utf8(path).filename().empty())
            return "The selected programming target has no file name";
    } catch (...) {
        return "The selected programming target is not valid UTF-8 or cannot be represented natively";
    }
    if (state().configuration_loading) return "Programming configurations are loading";
    const configuration_t* config = selected_configuration();
    const char* required_name = required == configuration_kind_t::launch
        ? "Launch" : required == configuration_kind_t::test ? "Test" : "Task";
    if (!config)
        return std::string("Select an explicit ") + required_name +
            " configuration before targeting this file";
    if (config->kind != required)
        return "The selected programming configuration is a " + kind_name(config->kind) +
            "; select an explicit " + required_name + " configuration";
    if (config->command.find("${file}") == std::string::npos)
        return "The selected configuration command does not bind the exact target with ${file}";
    std::unique_lock<std::mutex> lock(state().mutex, std::try_to_lock);
    if (!lock.owns_lock()) return "Programming task state is busy; try again";
    const auto active = state().active_runs.find(config->id);
    if (active != state().active_runs.end() && active->second &&
        !active->second->terminal.load(std::memory_order_acquire))
        return "The selected configuration is already running";
    return {};
}

bool parse_configuration(const nlohmann::json& item, configuration_origin_t origin,
                         configuration_t& result, std::string& error) {
    if (!item.is_object()) {
        error = "A configuration entry is not an object";
        return false;
    }
    result.source_id = item.value("id", std::string{});
    const std::string name = item.value("name", std::string{});
    const std::string command = item.value("command", std::string{});
    const std::string cwd = item.value("cwd", std::string{});
    const std::string output_channel = item.value("output_channel", std::string{});
    if (name.size() > 127 || command.size() > 8192 || cwd.size() > 1024 ||
        output_channel.size() > 96) {
        error = "Configuration fields exceed their documented size bounds";
        return false;
    }
    result.name = trim(name);
    result.command = command;
    result.cwd = cwd;
    result.output_channel = trim(output_channel);
    if (result.output_channel.empty() && result.name.size() > 96) {
        error = "Configurations with names longer than 96 bytes require an explicit Output channel";
        return false;
    }
    result.problem_matcher = item.value("problem_matcher", std::string("none"));
    const std::string kind = item.value("kind", std::string("task"));
    if (kind != "task" && kind != "launch" && kind != "test") {
        error = "Configuration kind must be task, launch, or test";
        return false;
    }
    result.kind = kind == "launch" ? configuration_kind_t::launch :
        kind == "test" ? configuration_kind_t::test : configuration_kind_t::task;
    result.origin = origin;
    if (!safe_identifier(result.source_id) || result.name.empty() || trim(result.command).empty() ||
        !control_free(result.name) || !control_free(result.command) || !control_free(result.cwd) ||
        !control_free(result.output_channel)) {
        error = "Every configuration requires a safe id, visible name, and explicit command";
        return false;
    }
    if (result.problem_matcher != "none" && result.problem_matcher != "msvc" &&
        result.problem_matcher != "gcc" && result.problem_matcher != "generic") {
        error = "Problem matcher must be none, msvc, gcc, or generic";
        return false;
    }
    result.id = origin == configuration_origin_t::project
        ? "project." + result.source_id : "user." + result.source_id;
    return true;
}

bool parse_configuration_document(const nlohmann::json& root, configuration_origin_t origin,
                                  std::vector<configuration_t>& output, std::string& error) {
    if (!root.is_object() || root.value("version", 0) != 1 ||
        !root.contains("configurations") || !root["configurations"].is_array()) {
        error = "Task configuration JSON must use version 1 and a configurations array";
        return false;
    }
    if (root["configurations"].size() > 64) {
        error = "A configuration source may contain at most 64 entries";
        return false;
    }
    std::vector<std::string> ids;
    for (const auto& item : root["configurations"]) {
        configuration_t config;
        if (!parse_configuration(item, origin, config, error)) return false;
        if (std::find(ids.begin(), ids.end(), config.id) != ids.end()) {
            error = "Configuration ids must be unique within their source";
            return false;
        }
        ids.push_back(config.id);
        output.push_back(std::move(config));
    }
    return true;
}

nlohmann::json serialize_user_configurations() {
    nlohmann::json root = nlohmann::json::object();
    root["version"] = 1;
    root["configurations"] = nlohmann::json::array();
    for (const auto& config : state().configurations) {
        if (config.origin != configuration_origin_t::user) continue;
        root["configurations"].push_back({
            {"id", config.source_id}, {"name", config.name},
            {"kind", kind_name(config.kind)}, {"command", config.command},
            {"cwd", config.cwd}, {"output_channel", config.output_channel},
            {"problem_matcher", config.problem_matcher}
        });
    }
    return root;
}

bool parse_user_configurations(const std::string& payload,
                               std::vector<configuration_t>& output, std::string& error) {
    if (payload.empty()) return true;
    if (payload.size() > 1024U * 1024U) {
        error = "Saved user task configurations exceed 1 MiB";
        return false;
    }
    try {
        return parse_configuration_document(nlohmann::json::parse(payload),
            configuration_origin_t::user, output, error);
    } catch (const std::exception& exception) {
        error = std::string("User task configuration JSON is invalid: ") + exception.what();
        return false;
    }
}

void apply_configuration_snapshot(std::uint64_t generation, std::string project_root,
                                  std::vector<configuration_t> configurations,
                                  std::string error, bool explicit_reload) {
    static_cast<void>(explicit_reload);
    auto& store = state();
    if (store.configuration_generation.load(std::memory_order_acquire) != generation ||
        store.project_root != project_root)
        return;
    store.configuration_loading = false;
    if (!error.empty()) {
        store.configuration_error = std::move(error);
        return;
    }
    store.configurations = std::move(configurations);
    store.configuration_error.clear();
    const auto selected = std::find_if(store.configurations.begin(), store.configurations.end(),
        [&](const configuration_t& config) { return config.id == store.selected_id; });
    if (selected == store.configurations.end())
        store.selected_id = store.configurations.empty() ? std::string{} : store.configurations.front().id;
    store.editor.loaded = false;
}

bool schedule_configuration_reload(bool explicit_reload, std::string& error) {
    auto& store = state();
    if (store.editor.save_in_flight) {
        error = "Wait for task configuration persistence to finish before reloading";
        return false;
    }
    if (store.editor.dirty) {
        error = "Save the edited task configuration before reloading";
        return false;
    }
    const std::string project_root = file_browser::current_dir;
    std::unique_lock<std::recursive_mutex> settings_lock(sa_settings_detail::io_mutex(), std::try_to_lock);
    if (!settings_lock.owns_lock()) {
        error = "Settings are busy; task configurations will reload when persistence finishes";
        return false;
    }
    const std::string user_payload = g_sa_settings.programming_tasks_json;
    settings_lock.unlock();
    if (user_payload.size() > 1024U * 1024U) {
        store.project_root = project_root;
        error = "Saved user task configurations exceed 1 MiB";
        return false;
    }
    store.project_root = project_root;
    store.configuration_loading = true;
    store.configuration_error.clear();
    const std::uint64_t generation = store.configuration_generation.fetch_add(
        1, std::memory_order_acq_rel) + 1;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (user_payload.size() > 64U * 1024U) {
        store.configuration_loading = false;
        error = "Studio preview accepts up to 64 KiB of user task configuration fixtures";
        return false;
    }
    std::vector<configuration_t> users;
    if (!parse_user_configurations(user_payload, users, error)) {
        store.configuration_loading = false;
        return false;
    }
    apply_configuration_snapshot(generation, project_root, std::move(users), {}, explicit_reload);
    error.clear();
    return true;
#else
    try {
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "programming_tasks";
    submission.label = "programming.load_project_configurations";
    submission.thread_class = "blocking_file_io";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 4;
    submission.generation = generation;
    submission.ui_access_policy = "immutable_snapshots_only";
    submission.failure_policy = "typed_diagnostic";
    submission.body = [generation, project_root, user_payload, explicit_reload]() mutable {
        std::vector<configuration_t> configurations;
        std::string load_error;
        try {
        const bool users_loaded = parse_user_configurations(
            user_payload, configurations, load_error);
        if (users_loaded && !project_root.empty()) {
            const std::filesystem::path path = std::filesystem::path(project_root) / ".aida" / "tasks.json";
            std::error_code ec;
            const bool exists = std::filesystem::is_regular_file(path, ec);
            if (ec) {
                load_error = "Project .aida/tasks.json could not be inspected: " + ec.message();
            } else if (exists) {
                const auto size = std::filesystem::file_size(path, ec);
                if (ec || size > 1024U * 1024U) {
                    load_error = "Project .aida/tasks.json is unavailable or exceeds 1 MiB";
                } else {
                    std::ifstream stream(path, std::ios::binary);
                    std::string content(static_cast<std::size_t>(size), '\0');
                    if (!stream.is_open() ||
                        (!content.empty() && !stream.read(content.data(), static_cast<std::streamsize>(content.size()))) ||
                        stream.bad()) {
                        load_error = "Project .aida/tasks.json could not be read completely";
                    } else {
                        try {
                            static_cast<void>(parse_configuration_document(nlohmann::json::parse(content),
                                configuration_origin_t::project, configurations, load_error));
                        } catch (const std::exception& exception) {
                            load_error = std::string("Project .aida/tasks.json is invalid: ") + exception.what();
                        }
                    }
                }
            }
        }
        } catch (const std::exception& exception) {
            load_error = std::string("Task configuration loading failed: ") + exception.what();
        } catch (...) {
            load_error = "Task configuration loading failed with an unknown exception";
        }
        bool posted = false;
        try {
            posted = aida::ui_thread::post(
                [generation, project_root, configurations = std::move(configurations),
                 load_error = std::move(load_error), explicit_reload]() mutable {
                    apply_configuration_snapshot(generation, std::move(project_root),
                        std::move(configurations), std::move(load_error), explicit_reload);
                }, "programming_tasks", "configuration_load_result", "worker_result");
        } catch (...) {
            posted = false;
        }
        if (!posted) {
            state().configuration_dispatch_failure_generation.store(generation, std::memory_order_release);
            diag::log_tagged("programming_tasks", "configuration_load_dispatch_rejected");
        }
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        store.configuration_loading = false;
        error = "Project task configuration loading could not be scheduled: " + submitted.reject_reason;
        store.configuration_error = error;
        return false;
    }
    error.clear();
    return true;
    } catch (const std::exception& exception) {
        store.configuration_loading = false;
        error = std::string("Project task configuration loading could not be scheduled: ") + exception.what();
        store.configuration_error = error;
        return false;
    } catch (...) {
        store.configuration_loading = false;
        error = "Project task configuration loading could not be scheduled due to an unknown exception";
        store.configuration_error = error;
        return false;
    }
#endif
}

bool persist_user_configurations(std::string& error, bool clears_editor_dirty = true) {
    auto& store = state();
    if (store.editor.save_in_flight) {
        error = "Task configuration persistence is already in progress";
        return false;
    }
    const std::string payload = serialize_user_configurations().dump();
    if (payload.size() > 1024U * 1024U) {
        error = "User task configurations exceed 1 MiB";
        return false;
    }
    std::unique_lock<std::recursive_mutex> settings_lock(sa_settings_detail::io_mutex(), std::try_to_lock);
    if (!settings_lock.owns_lock()) {
        error = "Settings persistence is busy; try again";
        return false;
    }
    g_sa_settings.programming_tasks_json = payload;
    g_sa_settings.programming_selected_task_id = store.selected_id;
    settings_lock.unlock();
    std::uint64_t generation = 0;
    const auto requested = aida::settings_persistence::request_save(g_sa_settings,
        &generation);
    if (!aida::settings_persistence::accepted(requested)) {
        error = "Task configuration persistence could not capture an immutable settings snapshot";
        return false;
    }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (clears_editor_dirty) store.editor.dirty = false;
    store.editor.save_in_flight = false;
#else
    store.editor.save_in_flight = true;
    store.editor.clear_dirty_on_commit = clears_editor_dirty;
    store.editor.settings_generation = generation;
    store.editor.persistence_payload = payload;
#endif
    error.clear();
    return true;
}

void ensure_initialized() {
    auto& store = state();
    if (store.configuration_loading &&
        store.configuration_dispatch_failure_generation.load(std::memory_order_acquire) ==
            store.configuration_generation.load(std::memory_order_acquire)) {
        store.configuration_loading = false;
        store.configuration_error = "Project task configuration result could not reach the UI thread";
    }
    if (store.editor.save_in_flight) {
        const auto persistence = aida::settings_persistence::status();
        if (persistence.committed_generation >= store.editor.settings_generation) {
            store.editor.save_in_flight = false;
            if (store.editor.clear_dirty_on_commit &&
                serialize_user_configurations().dump() == store.editor.persistence_payload) {
                store.editor.dirty = false;
                store.editor.validation_error.clear();
            }
            store.editor.persistence_payload.clear();
        } else if (!persistence.pending && persistence.failed &&
            persistence.generation >= store.editor.settings_generation) {
            store.editor.save_in_flight = false;
            if (store.editor.clear_dirty_on_commit) {
                store.editor.dirty = true;
                store.editor.validation_error = persistence.error.empty()
                    ? "Task configurations could not be saved" : persistence.error;
            } else {
                store.configuration_error = persistence.error.empty()
                    ? "Task configuration selection could not be saved" : persistence.error;
            }
            store.editor.persistence_payload.clear();
        }
    }
    if (!store.initialized) {
        store.initialized = true;
        store.selected_id = g_sa_settings.programming_selected_task_id;
        std::string error;
        if (!schedule_configuration_reload(false, error))
            store.configuration_error = std::move(error);
    } else if (store.project_root != file_browser::current_dir) {
        std::string error;
        if (!schedule_configuration_reload(false, error))
            store.configuration_error = std::move(error);
    }
}

const configuration_t* selected_configuration() {
    ensure_initialized();
    const auto& store = state();
    const auto found = std::find_if(store.configurations.begin(), store.configurations.end(),
        [&](const configuration_t& config) { return config.id == store.selected_id; });
    return found == store.configurations.end() ? nullptr : &*found;
}

std::string channel_prefix(const std::string& channel) {
    return "[Task:" + channel + "] ";
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
std::string strip_terminal_sequences(std::string_view value) {
    std::string output;
    output.reserve(value.size());
    enum class state_t : std::uint8_t { text, escape, csi, osc, osc_escape };
    state_t parser = state_t::text;
    for (char ch : value) {
        switch (parser) {
        case state_t::text:
            if (ch == '\x1b') parser = state_t::escape;
            else output.push_back(ch);
            break;
        case state_t::escape:
            parser = ch == '[' ? state_t::csi : ch == ']' ? state_t::osc : state_t::text;
            break;
        case state_t::csi:
            if (ch >= '@' && ch <= '~') parser = state_t::text;
            break;
        case state_t::osc:
            if (ch == '\x07') parser = state_t::text;
            else if (ch == '\x1b') parser = state_t::osc_escape;
            break;
        case state_t::osc_escape:
            parser = ch == '\\' ? state_t::text : state_t::osc;
            break;
        }
    }
    return output;
}

void publish_line(const std::shared_ptr<run_state_t>& run, std::string line) {
    if (!run || line.empty()) return;
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        const auto generation = state().generations.find(run->configuration.source.id);
        if (generation == state().generations.end() || generation->second != run->generation)
            return;
    }
    for (char& ch : line)
        if (static_cast<unsigned char>(ch) < 32 && ch != '\t') ch = ' ';
    line = bounded(std::move(line), 8192);
    output_log::push(bottom_tab_t::output, channel_prefix(run->configuration.channel) + line);
}

bool current_generation(const std::shared_ptr<run_state_t>& run) {
    if (!run) return false;
    std::lock_guard<std::mutex> lock(state().mutex);
    const auto found = state().generations.find(run->configuration.source.id);
    return found != state().generations.end() && found->second == run->generation;
}

std::optional<problem_t> parse_problem(const run_state_t& run, const std::string& line) {
    if (run.configuration.source.problem_matcher == "none") return std::nullopt;
    static const std::regex msvc(
        R"(^(.+)\(([0-9]+)(?:,([0-9]+))?\)\s*:\s*(fatal error|error|warning|note)[^:]*:\s*(.+)$)",
        std::regex::ECMAScript | std::regex::icase);
    static const std::regex gcc(
        R"(^(.+):([0-9]+):(?:([0-9]+):)?\s*(fatal error|error|warning|note)\s*:\s*(.+)$)",
        std::regex::ECMAScript | std::regex::icase);
    static const std::regex generic(
        R"(^(.+):([0-9]+)(?::([0-9]+))?:\s*(.+)$)", std::regex::ECMAScript);
    std::smatch match;
    const bool generic_matcher = run.configuration.source.problem_matcher == "generic";
    const bool matched = run.configuration.source.problem_matcher == "msvc"
        ? std::regex_match(line, match, msvc)
        : generic_matcher ? std::regex_match(line, match, generic)
                          : std::regex_match(line, match, gcc);
    if (!matched) return std::nullopt;
    problem_t problem;
    problem.path = trim(match[1].str());
    problem.line = (std::max)(1, std::atoi(match[2].str().c_str()));
    problem.column = match[3].matched ? (std::max)(1, std::atoi(match[3].str().c_str())) : 1;
    problem.severity = generic_matcher ? "information" : trim(match[4].str());
    std::transform(problem.severity.begin(), problem.severity.end(), problem.severity.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    problem.message = bounded(trim(match[generic_matcher ? 4 : 5].str()), 2048);
    std::filesystem::path path(problem.path);
    if (path.is_relative() && !run.configuration.cwd.empty())
        path = std::filesystem::path(run.configuration.cwd) / path;
    problem.path = path.lexically_normal().string();
    return problem;
}

void publish_problem(const std::shared_ptr<run_state_t>& run, const problem_t& problem) {
    if (!run || !current_generation(run) ||
        run->cancellation_requested.load(std::memory_order_acquire)) return;
    const std::uint32_t ordinal = run->problem_count.fetch_add(1, std::memory_order_acq_rel) + 1U;
    state().retained_problem_count.fetch_add(1, std::memory_order_acq_rel);
    const bool error = problem.severity.find("error") != std::string::npos;
    task_center::diagnostic_registration_t diagnostic;
    diagnostic.id = "programming.problem." + run->id + "." + std::to_string(ordinal);
    diagnostic.task_id = run->id;
    diagnostic.owner = "Programming " + kind_name(run->configuration.source.kind);
    diagnostic.target = problem.path + ":" + std::to_string(problem.line) + ":" +
        std::to_string(problem.column);
    diagnostic.summary = problem.message;
    diagnostic.details = run->configuration.source.name + " - " + problem.severity;
    diagnostic.log_link = run->configuration.channel;
    diagnostic.severity = error ? task_center::diagnostic_severity_t::error :
        problem.severity == "warning" ? task_center::diagnostic_severity_t::warning :
        task_center::diagnostic_severity_t::information;
    diagnostic.raised_ms = now_ms();
    const std::string path = problem.path;
    const int line = problem.line;
    const int column = problem.column;
    diagnostic.callbacks.focus = [path, line, column] {
        static_cast<void>(aida::ui_thread::post([path, line, column] {
            const std::string filename = std::filesystem::path(path).filename().string();
            static_cast<void>(file_tabs::request_document_open(path, filename, line - 1, column - 1));
            static_cast<void>(application_views::open_or_focus(stable_view_id_t("document.code")));
        }, "programming_tasks", "problem_focus", "task_center_callback"));
    };
    diagnostic.callbacks.open_log = [channel = run->configuration.channel] {
        static_cast<void>(aida::ui_thread::post([channel] {
            state().selected_channel = channel;
            static_cast<void>(application_views::open_or_focus(stable_view_id_t("view.output")));
        }, "programming_tasks", "problem_open_log", "task_center_callback"));
    };
    diagnostic.callbacks.retry = [id = run->configuration.source.id] {
        return aida::ui_thread::post([id] {
            auto& store = state();
            const auto found = std::find_if(store.configurations.begin(), store.configurations.end(),
                [&](const configuration_t& config) { return config.id == id; });
            if (found == store.configurations.end()) return;
            std::string error_text;
            auto resolved = resolve_configuration(*found, error_text);
            if (!resolved) {
                store.configuration_error = std::move(error_text);
                return;
            }
            store.pending_run = std::move(*resolved);
            store.run_review_open = true;
            static_cast<void>(application_views::open_or_focus(stable_view_id_t("view.output")));
        }, "programming_tasks", "problem_retry", "task_center_callback");
    };
    static_cast<void>(task_center::raise_diagnostic(std::move(diagnostic)));
}
#endif

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
void consume_line(const std::shared_ptr<run_state_t>& run, std::string line) {
    if (!run) return;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    line = strip_terminal_sequences(line);
    if (line.size() > 8192) line = line.substr(0, 8192) + " [line truncated]";
    publish_line(run, line);
    if (const auto problem = parse_problem(*run, line)) publish_problem(run, *problem);
}

std::wstring widen(const std::string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), size) != size)
        return {};
    return result;
}

void terminate_process_tree(const std::shared_ptr<run_state_t>& run) {
    if (!run) return;
    run->cancellation_requested.store(true, std::memory_order_release);
    std::unique_lock<std::mutex> lock(run->process_mutex, std::try_to_lock);
    if (lock.owns_lock() && run->job != INVALID_HANDLE_VALUE)
        TerminateJobObject(run->job, ERROR_CANCELLED);
}

void close_process_handles(const std::shared_ptr<run_state_t>& run) {
    if (!run) return;
    std::lock_guard<std::mutex> lock(run->process_mutex);
    if (run->output_read != INVALID_HANDLE_VALUE) CloseHandle(run->output_read);
    if (run->process != INVALID_HANDLE_VALUE) CloseHandle(run->process);
    if (run->job != INVALID_HANDLE_VALUE) CloseHandle(run->job);
    run->output_read = INVALID_HANDLE_VALUE;
    run->process = INVALID_HANDLE_VALUE;
    run->job = INVALID_HANDLE_VALUE;
}

std::string win32_failure(const char* operation, DWORD error) {
    return std::string(operation) + " failed (Win32 " + std::to_string(error) + ")";
}

bool execute_process(const std::shared_ptr<run_state_t>& run, DWORD& exit_code, std::string& error) {
    if (!run) {
        error = "The programming task state is unavailable";
        return false;
    }
    if (run->cancellation_requested.load(std::memory_order_acquire)) {
        error = "Cancellation was requested before the process started";
        return false;
    }
    if (!run->configuration.cwd.empty()) {
        std::error_code ec;
        if (!std::filesystem::is_directory(run->configuration.cwd, ec)) {
            error = ec ? "The resolved working directory is not accessible: " + ec.message()
                       : "The resolved working directory does not exist or is not accessible";
            return false;
        }
    }
    std::wstring command = widen(run->configuration.command);
    std::wstring cwd = widen(run->configuration.cwd);
    if (command.empty()) {
        error = "The resolved command is not valid UTF-8";
        return false;
    }
    if (!run->configuration.cwd.empty() && cwd.empty()) {
        error = "The resolved working directory is not valid UTF-8";
        return false;
    }
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE read_pipe = INVALID_HANDLE_VALUE;
    HANDLE write_pipe = INVALID_HANDLE_VALUE;
    if (!CreatePipe(&read_pipe, &write_pipe, &security, 0)) {
        error = win32_failure("CreatePipe", GetLastError());
        return false;
    }
    if (!SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0)) {
        const DWORD failure = GetLastError();
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        error = win32_failure("SetHandleInformation", failure);
        return false;
    }
    HANDLE input_null = CreateFileW(L"NUL", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input_null == INVALID_HANDLE_VALUE) {
        const DWORD failure = GetLastError();
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        error = win32_failure("CreateFileW(NUL)", failure);
        return false;
    }
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) {
        const DWORD failure = GetLastError();
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        CloseHandle(input_null);
        error = win32_failure("CreateJobObjectW", failure);
        return false;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        const DWORD failure = GetLastError();
        CloseHandle(job);
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        CloseHandle(input_null);
        error = win32_failure("SetInformationJobObject", failure);
        return false;
    }
    SIZE_T attributes_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributes_size);
    std::vector<unsigned char> attributes_storage(attributes_size);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes_storage.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attributes_size)) {
        const DWORD failure = GetLastError();
        CloseHandle(job);
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        CloseHandle(input_null);
        error = win32_failure("InitializeProcThreadAttributeList", failure);
        return false;
    }
    HANDLE inherited[] = {write_pipe, input_null};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited, sizeof(inherited), nullptr, nullptr)) {
        const DWORD failure = GetLastError();
        DeleteProcThreadAttributeList(attributes);
        CloseHandle(job);
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        CloseHandle(input_null);
        error = win32_failure("UpdateProcThreadAttribute", failure);
        return false;
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input_null;
    startup.StartupInfo.hStdOutput = write_pipe;
    startup.StartupInfo.hStdError = write_pipe;
    startup.lpAttributeList = attributes;
    PROCESS_INFORMATION process{};
    std::vector<wchar_t> command_line(command.begin(), command.end());
    command_line.push_back(L'\0');
    const BOOL created = CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
        nullptr, cwd.empty() ? nullptr : cwd.c_str(), &startup.StartupInfo, &process);
    const DWORD create_error = created ? ERROR_SUCCESS : GetLastError();
    DeleteProcThreadAttributeList(attributes);
    CloseHandle(write_pipe);
    CloseHandle(input_null);
    if (!created) {
        CloseHandle(job);
        CloseHandle(read_pipe);
        error = win32_failure("CreateProcessW", create_error);
        return false;
    }
    if (!AssignProcessToJobObject(job, process.hProcess)) {
        const DWORD failure = GetLastError();
        TerminateProcess(process.hProcess, failure);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        CloseHandle(job);
        CloseHandle(read_pipe);
        error = win32_failure("AssignProcessToJobObject", failure);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(run->process_mutex);
        run->job = job;
        run->process = process.hProcess;
        run->output_read = read_pipe;
    }
    if (run->cancellation_requested.load(std::memory_order_acquire)) {
        TerminateJobObject(job, ERROR_CANCELLED);
        CloseHandle(process.hThread);
        static_cast<void>(WaitForSingleObject(process.hProcess, 5000));
        close_process_handles(run);
        error = "Cancellation was requested before the process resumed";
        return false;
    }
    if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
        const DWORD failure = GetLastError();
        TerminateJobObject(job, failure);
        CloseHandle(process.hThread);
        close_process_handles(run);
        error = win32_failure("ResumeThread", failure);
        return false;
    }
    CloseHandle(process.hThread);
    std::string pending;
    std::array<char, 4096> buffer{};
    bool process_exited = false;
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &available, nullptr)) break;
        if (available != 0) {
            DWORD read = 0;
            const DWORD requested = (std::min)(available, static_cast<DWORD>(buffer.size()));
            if (!ReadFile(read_pipe, buffer.data(), requested, &read, nullptr) || read == 0) break;
            pending.append(buffer.data(), read);
            std::size_t newline = 0;
            while ((newline = pending.find('\n')) != std::string::npos) {
                consume_line(run, pending.substr(0, newline));
                pending.erase(0, newline + 1);
            }
            if (pending.size() > 65536) {
                consume_line(run, pending.substr(0, 8192) + " [line truncated]");
                pending.clear();
            }
            continue;
        }
        process_exited = WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0;
        if (process_exited) break;
        if (run->cancellation_requested.load(std::memory_order_acquire))
            TerminateJobObject(job, ERROR_CANCELLED);
        Sleep(10);
    }
    if (!pending.empty()) consume_line(run, std::move(pending));
    if (!process_exited) WaitForSingleObject(process.hProcess, 5000);
    exit_code = std::numeric_limits<DWORD>::max();
    static_cast<void>(GetExitCodeProcess(process.hProcess, &exit_code));
    close_process_handles(run);
    return true;
}
#endif

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
void finish_run(const std::shared_ptr<run_state_t>& run, task_center::task_state_t task_state,
                const std::string& summary, const std::string& diagnostic = {}) {
    if (!run) return;
    if (run->terminal.exchange(true, std::memory_order_acq_rel)) return;
    static_cast<void>(task_center::update_task(run->id, task_state, 1.0f,
        "Finished", summary, diagnostic, run->configuration.channel));
    {
        std::lock_guard<std::mutex> lock(state().mutex);
        const auto found = state().active_runs.find(run->configuration.source.id);
        if (found != state().active_runs.end() && found->second == run)
            state().active_runs.erase(found);
        state().last_run = run;
        state().active_count.store(state().active_runs.size(), std::memory_order_release);
    }
    publish_line(run, summary);
}

void run_worker(const std::shared_ptr<run_state_t>& run) {
    if (!run) return;
    if (run->cancellation_requested.load(std::memory_order_acquire)) {
        finish_run(run, task_center::task_state_t::cancelled,
            run->configuration.source.name + " was cancelled before launch");
        return;
    }
    static_cast<void>(task_center::update_task(run->id, task_center::task_state_t::running,
        -1.0f, "Starting external process"));
    DWORD exit_code = std::numeric_limits<DWORD>::max();
    std::string error;
    if (!execute_process(run, exit_code, error)) {
        if (run->cancellation_requested.load(std::memory_order_acquire))
            finish_run(run, task_center::task_state_t::cancelled,
                run->configuration.source.name + " was cancelled");
        else
            finish_run(run, task_center::task_state_t::failed, error,
                "programming.process_start." + run->id);
        return;
    }
    if (run->cancellation_requested.load(std::memory_order_acquire) || exit_code == ERROR_CANCELLED) {
        finish_run(run, task_center::task_state_t::cancelled,
            run->configuration.source.name + " was cancelled");
        return;
    }
    const std::uint32_t problems = run->problem_count.load(std::memory_order_acquire);
    if (exit_code == 0) {
        finish_run(run, task_center::task_state_t::completed,
            run->configuration.source.name + " completed" +
            (problems ? " with " + std::to_string(problems) + " problem(s)" : std::string{}));
    } else {
        finish_run(run, task_center::task_state_t::failed,
            run->configuration.source.name + " exited with code " + std::to_string(exit_code),
            "programming.exit." + run->id);
    }
}
#endif

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
void defer_registration_cleanup(const std::shared_ptr<run_state_t>& run, unsigned attempt) {
    if (!run) return;
    const bool posted = aida::ui_thread::post([run, attempt] {
        std::unique_lock<std::mutex> lock(state().mutex, std::try_to_lock);
        if (!lock.owns_lock()) {
            if (attempt < 8) defer_registration_cleanup(run, attempt + 1);
            return;
        }
        const auto found = state().active_runs.find(run->configuration.source.id);
        if (found != state().active_runs.end() && found->second == run)
            state().active_runs.erase(found);
        state().active_count.store(state().active_runs.size(), std::memory_order_release);
    }, "programming_tasks", "registration_cleanup", "deferred_ui_cleanup");
    if (!posted)
        diag::log_tagged("programming_tasks", "registration_cleanup_dispatch_rejected_bounded");
}
#endif

operation_result_t start_run(const resolved_configuration_t& configuration) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(configuration);
    return {false, "External programming tasks require the native AiDA runtime"};
#else
    auto& store = state();
    auto run = std::make_shared<run_state_t>();
    {
        std::unique_lock<std::mutex> lock(store.mutex, std::try_to_lock);
        if (!lock.owns_lock())
            return {false, "Programming task state is busy; try again"};
        for (auto it = store.active_runs.begin(); it != store.active_runs.end();) {
            if (!it->second || it->second->terminal.load(std::memory_order_acquire))
                it = store.active_runs.erase(it);
            else
                ++it;
        }
        store.active_count.store(store.active_runs.size(), std::memory_order_release);
        if (store.active_runs.size() >= 128)
            return {false, "The programming task registry reached its 128-active-run bound"};
        if (store.active_runs.find(configuration.source.id) != store.active_runs.end())
        {
            const auto existing = store.active_runs.find(configuration.source.id);
            if (existing->second && existing->second->terminal.load(std::memory_order_acquire)) {
                store.active_runs.erase(existing);
                store.active_count.store(store.active_runs.size(), std::memory_order_release);
            } else {
                return {false, "This configuration is already running"};
            }
        }
        const bool new_channel = std::find(store.channels.begin(), store.channels.end(),
            configuration.channel) == store.channels.end();
        if (new_channel && store.channels.size() >= 256)
            return {false, "The programming Output channel registry reached its 256-channel bound"};
        run->generation = ++store.generations[configuration.source.id];
        run->id = "programming.run." + std::to_string(now_ms()) + "." +
            std::to_string(store.next_run++);
        run->configuration = configuration;
        store.active_runs[configuration.source.id] = run;
        store.last_run = run;
        store.active_count.store(store.active_runs.size(), std::memory_order_release);
        if (store.active_runs.size() == 1)
            store.retained_problem_count.store(0, std::memory_order_release);
        if (std::find(store.channels.begin(), store.channels.end(), configuration.channel) == store.channels.end())
            store.channels.push_back(configuration.channel);
        store.selected_channel = configuration.channel;
    }
    task_center::task_registration_t registration;
    registration.id = run->id;
    registration.source = "programming.config";
    registration.owner = configuration.source.kind == configuration_kind_t::launch
        ? "Programming Launch" : configuration.source.kind == configuration_kind_t::test
            ? "Programming Test" : "Programming Task";
    registration.owner_view = "view.output";
    registration.owner_action = "programming.task.run";
    registration.project = file_browser::current_dir;
    registration.target = configuration.channel;
    registration.label = configuration.source.name;
    registration.stage = "Queued for external process execution";
    registration.affected_entity = configuration.source.id;
    registration.queued_ms = now_ms();
    registration.cancellation_is_safe = true;
    registration.callbacks.cancel = [weak = std::weak_ptr<run_state_t>(run)] {
        const auto locked = weak.lock();
        if (!locked || locked->terminal.load(std::memory_order_acquire)) return false;
        terminate_process_tree(locked);
        return true;
    };
    registration.callbacks.retry = [id = configuration.source.id] {
        return aida::ui_thread::post([id] {
            auto& current = state();
            const auto found = std::find_if(current.configurations.begin(), current.configurations.end(),
                [&](const configuration_t& item) { return item.id == id; });
            if (found == current.configurations.end()) return;
            std::string error;
            auto resolved = resolve_configuration(*found, error);
            if (!resolved) {
                current.configuration_error = std::move(error);
                return;
            }
            current.pending_run = std::move(*resolved);
            current.run_review_open = true;
            static_cast<void>(application_views::open_or_focus(stable_view_id_t("view.output")));
        }, "programming_tasks", "task_retry", "task_center_callback");
    };
    registration.callbacks.focus = [channel = configuration.channel] {
        static_cast<void>(aida::ui_thread::post([channel] {
            state().selected_channel = channel;
            static_cast<void>(application_views::open_or_focus(stable_view_id_t("view.output")));
        }, "programming_tasks", "task_focus", "task_center_callback"));
    };
    registration.callbacks.open_log = registration.callbacks.focus;
    if (!task_center::register_task(std::move(registration))) {
        std::unique_lock<std::mutex> lock(store.mutex, std::try_to_lock);
        if (lock.owns_lock()) {
            store.active_runs.erase(configuration.source.id);
            store.active_count.store(store.active_runs.size(), std::memory_order_release);
        } else {
            run->terminal.store(true, std::memory_order_release);
            store.active_count.fetch_sub(1, std::memory_order_acq_rel);
            defer_registration_cleanup(run, 0);
        }
        return {false, "The Task Center rejected the programming run registration"};
    }
    publish_line(run, configuration.source.name + " started");
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "programming_tasks";
    submission.label = "programming.external_process";
    submission.thread_class = "external_process_io";
    submission.domain = aida::infra::executor::domain_t::external_tool;
    submission.priority = 3;
    submission.session_id = run->id.c_str();
    submission.target_id = run->configuration.source.id.c_str();
    submission.generation = run->generation;
    submission.diagnostic_id = run->id.c_str();
    submission.ui_access_policy = "immutable_snapshots_only";
    submission.failure_policy = "typed_diagnostic";
    submission.shutdown_policy = "cancel";
    submission.cancel_hook = [weak = std::weak_ptr<run_state_t>(run)] {
        if (const auto locked = weak.lock()) terminate_process_tree(locked);
    };
    submission.body = [run] {
        try {
            run_worker(run);
        } catch (const std::exception& exception) {
            finish_run(run, task_center::task_state_t::failed,
                std::string("Programming task failed: ") + exception.what(),
                "programming.exception." + run->id);
        } catch (...) {
            finish_run(run, task_center::task_state_t::failed,
                "Programming task failed with an unknown exception",
                "programming.exception." + run->id);
        }
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        finish_run(run, task_center::task_state_t::failed,
            "The external-task executor rejected the run: " + submitted.reject_reason,
            "programming.executor." + run->id);
        return {false, submitted.reject_reason};
    }
    return {true, {}};
#endif
}

void load_editor(int index) {
    auto& store = state();
    auto& editor = store.editor;
    const bool save_in_flight = editor.save_in_flight;
    editor = {};
    editor.save_in_flight = save_in_flight;
    editor.selected = index;
    editor.loaded = true;
    if (index < 0 || index >= static_cast<int>(store.configurations.size())) return;
    const auto& config = store.configurations[static_cast<std::size_t>(index)];
    std::snprintf(editor.name.data(), editor.name.size(), "%s", config.name.c_str());
    std::snprintf(editor.command.data(), editor.command.size(), "%s", config.command.c_str());
    std::snprintf(editor.cwd.data(), editor.cwd.size(), "%s", config.cwd.c_str());
    std::snprintf(editor.channel.data(), editor.channel.size(), "%s", config.output_channel.c_str());
    editor.kind = config.kind == configuration_kind_t::launch ? 1 :
        config.kind == configuration_kind_t::test ? 2 : 0;
    editor.matcher = matcher_index(config.problem_matcher);
}

void add_user_configuration() {
    auto& store = state();
    const std::size_t user_count = static_cast<std::size_t>(std::count_if(
        store.configurations.begin(), store.configurations.end(), [](const configuration_t& config) {
            return config.origin == configuration_origin_t::user;
        }));
    if (user_count >= 64) {
        store.editor.validation_error = "User task configurations reached the 64-entry bound";
        return;
    }
    configuration_t config;
    config.source_id = "config_" + std::to_string(now_ms()) + "_" +
        std::to_string(store.next_configuration++);
    config.id = "user." + config.source_id;
    config.name = "New Task";
    config.cwd = "${workspaceFolder}";
    config.problem_matcher = "none";
    config.origin = configuration_origin_t::user;
    store.configurations.push_back(std::move(config));
    store.selected_id = store.configurations.back().id;
    load_editor(static_cast<int>(store.configurations.size()) - 1);
    store.editor.dirty = true;
}

void duplicate_configuration(int index) {
    auto& store = state();
    const std::size_t user_count = static_cast<std::size_t>(std::count_if(
        store.configurations.begin(), store.configurations.end(), [](const configuration_t& config) {
            return config.origin == configuration_origin_t::user;
        }));
    if (user_count >= 64) {
        store.configuration_error = "User task configurations reached the 64-entry bound";
        return;
    }
    if (index < 0 || index >= static_cast<int>(store.configurations.size())) {
        store.configuration_error = "Select a configuration to duplicate";
        return;
    }
    configuration_t copy = store.configurations[static_cast<std::size_t>(index)];
    copy.source_id = "config_" + std::to_string(now_ms()) + "_" +
        std::to_string(store.next_configuration++);
    copy.id = "user." + copy.source_id;
    copy.name = bounded(copy.name + " Copy", 127);
    copy.origin = configuration_origin_t::user;
    store.configurations.push_back(std::move(copy));
    store.selected_id = store.configurations.back().id;
    load_editor(static_cast<int>(store.configurations.size()) - 1);
    store.editor.dirty = true;
    store.configure_open = true;
    store.configuration_error.clear();
}

bool save_editor() {
    auto& store = state();
    auto& editor = store.editor;
    if (editor.selected < 0 || editor.selected >= static_cast<int>(store.configurations.size())) {
        editor.validation_error = "Select a user configuration first";
        return false;
    }
    auto& config = store.configurations[static_cast<std::size_t>(editor.selected)];
    if (config.origin != configuration_origin_t::user) {
        editor.validation_error = "Project configurations are read-only here; edit .aida/tasks.json in the code editor";
        return false;
    }
    const std::string name = trim(editor.name.data());
    const std::string command = trim(editor.command.data());
    const std::string channel = trim(editor.channel.data());
    if (name.empty() || command.empty()) {
        editor.validation_error = "Name and command are required";
        return false;
    }
    if (!control_free(name) || !control_free(command) || !control_free(editor.cwd.data()) ||
        !control_free(editor.channel.data())) {
        editor.validation_error = "Configuration fields cannot contain control characters or line breaks";
        return false;
    }
    if (channel.size() > 96) {
        editor.validation_error = "Output channel names may contain at most 96 bytes";
        return false;
    }
    if (channel.empty() && name.size() > 96) {
        editor.validation_error = "Names longer than 96 bytes require an explicit Output channel";
        return false;
    }
    config.name = bounded(name, 127);
    config.command = bounded(command, 8192);
    config.cwd = bounded(trim(editor.cwd.data()), 1024);
    config.output_channel = channel;
    config.kind = editor.kind == 1 ? configuration_kind_t::launch :
        editor.kind == 2 ? configuration_kind_t::test : configuration_kind_t::task;
    config.problem_matcher = matcher_name(editor.matcher);
    store.selected_id = config.id;
    editor.dirty = true;
    if (!persist_user_configurations(editor.validation_error)) return false;
    editor.validation_error = editor.save_in_flight ? "Saving task configuration..." : std::string{};
    return true;
}

void delete_selected_configuration() {
    auto& store = state();
    if (store.editor.save_in_flight) {
        store.editor.validation_error = "Wait for task configuration persistence to finish";
        return;
    }
    const int index = store.editor.selected;
    if (index < 0 || index >= static_cast<int>(store.configurations.size())) return;
    const auto& config = store.configurations[static_cast<std::size_t>(index)];
    if (config.origin != configuration_origin_t::user) return;
    {
        std::unique_lock<std::mutex> lock(store.mutex, std::try_to_lock);
        if (!lock.owns_lock()) {
            store.editor.validation_error = "Programming task state is busy; try again";
            return;
        }
        const auto active = store.active_runs.find(config.id);
        if (active != store.active_runs.end() && active->second &&
            !active->second->terminal.load(std::memory_order_acquire)) {
            store.editor.validation_error = "Stop the active run before deleting its configuration";
            return;
        }
    }
    store.configurations.erase(store.configurations.begin() + index);
    store.selected_id = store.configurations.empty() ? std::string{} :
        store.configurations[static_cast<std::size_t>((std::min)(index,
            static_cast<int>(store.configurations.size()) - 1))].id;
    std::string error;
    store.editor.dirty = true;
    if (!persist_user_configurations(error)) store.configuration_error = std::move(error);
    load_editor(-1);
}

void render_configuration_editor() {
    auto& store = state();
    auto& editor = store.editor;
    if (!editor.loaded) {
        const auto found = std::find_if(store.configurations.begin(), store.configurations.end(),
            [&](const configuration_t& config) { return config.id == store.selected_id; });
        load_editor(found == store.configurations.end() ? -1 :
            static_cast<int>(std::distance(store.configurations.begin(), found)));
    }
    const float area_height = (std::max)(180.0f, ImGui::GetContentRegionAvail().y - 48.0f);
    const float list_width = (std::min)(220.0f,
        (std::max)(150.0f, ImGui::GetContentRegionAvail().x * 0.34f));
    ImGui::BeginChild("##task_configuration_list", ImVec2(list_width, area_height), true);
    for (int index = 0; index < static_cast<int>(store.configurations.size()); ++index) {
        const auto& config = store.configurations[static_cast<std::size_t>(index)];
        const std::string label = config.name + (config.origin == configuration_origin_t::project
            ? "  [Project]" : "  [User]");
        if (ImGui::Selectable((label + "###task.config." + config.id).c_str(), editor.selected == index)) {
            store.selected_id = config.id;
            load_editor(index);
        }
    }
    ImGui::Separator();
    if (ImGui::Button("Add User Configuration", ImVec2(-1.0f, 0.0f))) add_user_configuration();
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("##task_configuration_editor", ImVec2(0.0f, area_height), false);
    const bool valid_selection = editor.selected >= 0 &&
        editor.selected < static_cast<int>(store.configurations.size());
    const bool read_only = valid_selection && store.configurations[static_cast<std::size_t>(editor.selected)].origin ==
        configuration_origin_t::project;
    if (!valid_selection) {
        ImGui::TextDisabled("Select a configuration or create a user configuration.");
        ImGui::EndChild();
        return;
    }
    if (read_only) {
        ImGui::TextDisabled("Project-owned: .aida/tasks.json");
        ImGui::SameLine();
        if (ImGui::SmallButton("Open Configuration File")) {
            const auto path = std::filesystem::path(file_browser::current_dir) / ".aida" / "tasks.json";
            file_browser::open_path(path.string());
            static_cast<void>(application_views::open_or_focus(stable_view_id_t("document.code")));
        }
    }
    ImGui::BeginDisabled(read_only);
    ImGui::SetNextItemWidth(-1.0f);
    editor.dirty |= ImGui::InputText("Name", editor.name.data(), editor.name.size());
    ImGui::SetNextItemWidth(-1.0f);
    editor.dirty |= ImGui::InputTextMultiline("Command", editor.command.data(), editor.command.size(), ImVec2(-1.0f, 88.0f));
    ImGui::SetNextItemWidth(-1.0f);
    editor.dirty |= ImGui::InputText("Working directory", editor.cwd.data(), editor.cwd.size());
    ImGui::SetNextItemWidth(-1.0f);
    editor.dirty |= ImGui::InputText("Output channel", editor.channel.data(), editor.channel.size());
    const char* kinds[] = {"Task", "Launch", "Test"};
    editor.dirty |= ImGui::Combo("Kind", &editor.kind, kinds, 3);
    const char* matchers[] = {"None", "MSVC", "GCC/Clang", "Generic file:line:column"};
    editor.dirty |= ImGui::Combo("Problem matcher", &editor.matcher, matchers, 4);
    ImGui::TextDisabled("Variables: ${workspaceFolder}, ${file}, ${fileDirname}");
    if (!editor.validation_error.empty())
        ImGui::TextColored(ImVec4(0.95f, 0.4f, 0.35f, 1.0f), "%s", editor.validation_error.c_str());
    ImGui::BeginDisabled(editor.save_in_flight || !editor.dirty);
    if (ImGui::Button(editor.save_in_flight ? "Saving..." : "Save Configuration"))
        static_cast<void>(save_editor());
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Delete...")) editor.delete_requested = true;
    if (editor.dirty && !store.configurations[static_cast<std::size_t>(editor.selected)].command.empty()) {
        ImGui::SameLine();
        if (ImGui::Button("Revert Edits")) load_editor(editor.selected);
    }
    ImGui::EndDisabled();
    ImGui::EndChild();
    constexpr const char* delete_popup =
        "Delete Task Configuration###programming.task.configuration.delete";
    if (editor.delete_requested && !ImGui::IsPopupOpen(delete_popup))
        design::open_dialog("programming.task.configuration.delete",
            "Delete Task Configuration");
    if (design::begin_dialog("programming.task.configuration.delete",
            "Delete Task Configuration", ImVec2(520.0f, 270.0f),
            ImVec2(400.0f, 230.0f))) {
        const bool selected_user = editor.selected >= 0 &&
            editor.selected < static_cast<int>(store.configurations.size()) &&
            store.configurations[static_cast<std::size_t>(editor.selected)].origin ==
                configuration_origin_t::user;
        const float footer_height = design::dialog_footer_reserve_height(
            "Delete Configuration", "Cancel");
        design::begin_dialog_body("programming_task_configuration_delete_body",
            footer_height);
        design::text(design::text_role_t::title,
            "Delete this user task configuration?");
        ImGui::TextWrapped("This removes only the saved configuration. Existing output and diagnostics remain.");
        if (!editor.validation_error.empty())
            design::text(design::text_role_t::caption,
                editor.validation_error.c_str());
        design::end_dialog_body();
        const auto footer = design::dialog_footer(
            "programming_task_configuration_delete_footer",
            "Delete Configuration", selected_user && !editor.save_in_flight, true);
        if (footer.confirmed) {
            const std::string retained_id = selected_user
                ? store.configurations[static_cast<std::size_t>(editor.selected)].id
                : std::string{};
            delete_selected_configuration();
            const bool removed = !retained_id.empty() &&
                std::none_of(store.configurations.begin(), store.configurations.end(),
                    [&](const configuration_t& configuration) {
                        return configuration.id == retained_id;
                    });
            if (removed) {
                editor.delete_requested = false;
                ImGui::CloseCurrentPopup();
            }
        } else if (footer.cancelled) {
            editor.delete_requested = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

}

void render_output_controls() {
    ensure_initialized();
    auto& store = state();
    ImGui::PushID("programming_tasks");
    const bool compact = ImGui::GetContentRegionAvail().x < 720.0f;
    const configuration_t* selected = selected_configuration();
    const char* preview = selected ? selected->name.c_str() : "No task configuration";
    ImGui::SetNextItemWidth((std::min)(260.0f, (std::max)(120.0f, ImGui::GetContentRegionAvail().x * 0.28f)));
    ImGui::BeginDisabled(store.editor.save_in_flight || store.configuration_loading);
    if (ImGui::BeginCombo("##task_configuration", preview)) {
        for (const auto& config : store.configurations) {
            const bool active = config.id == store.selected_id;
            if (ImGui::Selectable((config.name + "###task.select." + config.id).c_str(), active)) {
                store.selected_id = config.id;
                store.editor.loaded = false;
                std::string persistence_error;
                if (!persist_user_configurations(persistence_error, false))
                    store.configuration_error = std::move(persistence_error);
            }
        }
        if (store.configurations.empty()) ImGui::TextDisabled("No explicit user or project configurations");
        ImGui::EndCombo();
    }
    ImGui::EndDisabled();
    if (!compact) ImGui::SameLine();
	const int output_tab = static_cast<int>(bottom_tab_t::output);
	const auto run_action = application_ui::present_output_action(
		output_tab, "programming.task.run");
	ImGui::BeginDisabled(!run_action.enabled);
    if (ImGui::SmallButton("Run..."))
		static_cast<void>(application_ui::execute_output_action(output_tab,
            "programming.task.run", action_invocation_source_t::toolbar));
    ImGui::EndDisabled();
	design::tooltip_for_last_item(
		run_action.enabled ? run_action.description.c_str() : run_action.disabled_reason.c_str(),
		run_action.shortcut.empty() ? nullptr : run_action.shortcut.c_str());
    ImGui::SameLine();
	const auto configure_action = application_ui::present_output_action(
		output_tab, "programming.task.configure");
	ImGui::BeginDisabled(!configure_action.enabled);
    if (ImGui::SmallButton("Configure..."))
		static_cast<void>(application_ui::execute_output_action(output_tab,
            "programming.task.configure", action_invocation_source_t::toolbar));
	ImGui::EndDisabled();
	design::tooltip_for_last_item(configure_action.enabled
		? configure_action.description.c_str() : configure_action.disabled_reason.c_str(),
		configure_action.shortcut.empty() ? nullptr : configure_action.shortcut.c_str());
    if (has_active_run()) {
        ImGui::SameLine();
		const auto cancel_action = application_ui::present_output_action(
			output_tab, "programming.task.cancel");
		ImGui::BeginDisabled(!cancel_action.enabled);
        if (ImGui::SmallButton("Cancel"))
			static_cast<void>(application_ui::execute_output_action(output_tab,
                "programming.task.cancel", action_invocation_source_t::toolbar));
        ImGui::EndDisabled();
		design::tooltip_for_last_item(cancel_action.enabled
			? cancel_action.description.c_str() : cancel_action.disabled_reason.c_str(),
			cancel_action.shortcut.empty() ? nullptr : cancel_action.shortcut.c_str());
    }
    const std::size_t problems = problem_count();
    if (problems != 0) {
        ImGui::SameLine();
        const std::string label = "Problems (" + std::to_string(problems) + ")";
		const auto problems_action = application_ui::present_output_action(
			output_tab, "programming.show_problems");
		ImGui::BeginDisabled(!problems_action.enabled);
        if (ImGui::SmallButton(label.c_str()))
			static_cast<void>(application_ui::execute_output_action(output_tab,
                "programming.show_problems", action_invocation_source_t::toolbar));
		ImGui::EndDisabled();
		design::tooltip_for_last_item(problems_action.enabled
			? problems_action.description.c_str() : problems_action.disabled_reason.c_str(),
			problems_action.shortcut.empty() ? nullptr : problems_action.shortcut.c_str());
    }
    if (!compact) ImGui::SameLine();
    const char* channel_preview = store.selected_channel.empty() ? "All Output" : store.selected_channel.c_str();
    ImGui::SetNextItemWidth((std::min)(220.0f, (std::max)(110.0f, ImGui::GetContentRegionAvail().x)));
    if (ImGui::BeginCombo("##task_output_channel", channel_preview)) {
        if (ImGui::Selectable("All Output", store.selected_channel.empty())) store.selected_channel.clear();
        for (const auto& channel : store.channels)
            if (ImGui::Selectable(channel.c_str(), store.selected_channel == channel))
                store.selected_channel = channel;
        ImGui::EndCombo();
    }
    if (!store.configuration_error.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.95f, 0.4f, 0.35f, 1.0f), "Configuration error");
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", store.configuration_error.c_str());
    }
    if (store.configuration_loading) {
        ImGui::SameLine();
        ImGui::TextDisabled("Loading configurations...");
    }
    ImGui::PopID();
}

const char* task_state_label(task_center::task_state_t value) {
    switch (value) {
    case task_center::task_state_t::running: return "Running";
    case task_center::task_state_t::cancellation_requested: return "Cancelling";
    case task_center::task_state_t::completed: return "Completed";
    case task_center::task_state_t::partial: return "Partial";
    case task_center::task_state_t::cancelled: return "Cancelled";
    case task_center::task_state_t::failed: return "Failed";
    case task_center::task_state_t::timed_out: return "Timed out";
    case task_center::task_state_t::interrupted: return "Interrupted";
    case task_center::task_state_t::queued: return "Queued";
    }
    return "Unknown";
}

bool active_task_state(task_center::task_state_t value) {
    return value == task_center::task_state_t::queued ||
        value == task_center::task_state_t::running ||
        value == task_center::task_state_t::cancellation_requested;
}

script_run_identity_t script_run_identity(const task_center::task_snapshot_t& task,
                                          std::uint64_t snapshot_generation) {
    return {task.id, task.source, task.owner, task.label, task.queued_ms,
        snapshot_generation};
}

bool same_script_run(const task_center::task_snapshot_t& task,
                     const script_run_identity_t& identity) {
    return task.id == identity.id && task.source == identity.source &&
        task.owner == identity.owner && task.label == identity.label &&
        task.queued_ms == identity.queued_ms;
}

const task_center::task_snapshot_t* find_script_run(
    const task_center::immutable_snapshot_t& snapshot,
    const script_run_identity_t& identity) {
    const auto found = std::find_if(snapshot.tasks.begin(), snapshot.tasks.end(),
        [&](const task_center::task_snapshot_t& task) {
            return same_script_run(task, identity);
        });
    return found == snapshot.tasks.end() ? nullptr : &*found;
}

enum class script_run_action_t : std::uint8_t { cancel, retry, focus, open_log };

std::string script_run_action_unavailable_reason(
    const task_center::task_snapshot_t* task, script_run_action_t action) {
    if (!task)
        return "The retained run was removed or replaced; select the run again";
    switch (action) {
    case script_run_action_t::cancel:
        if (task->security_critical)
            return "Security-critical tasks cannot be cancelled";
        if (task->state == task_center::task_state_t::cancellation_requested)
            return "Cancellation is already pending owner confirmation";
        if (!active_task_state(task->state))
            return "Only an active run can be cancelled";
        if (!task->cancellable)
            return "This run owner did not register safe cancellation";
        return {};
    case script_run_action_t::retry:
        if (active_task_state(task->state))
            return "An active run cannot be retried";
        if (!task->retryable)
            return "This run owner did not register retry";
        return {};
    case script_run_action_t::focus:
        return task->focusable ? std::string{} :
            "This run owner did not register an output focus target";
    case script_run_action_t::open_log:
        return task->log_available ? std::string{} :
            "This run has no retained log target";
    }
    return "The run action is unavailable";
}

action_handler_result_t invoke_script_run_action(const script_run_identity_t& identity,
                                                 script_run_action_t action) {
    const auto current = task_center::snapshot();
    const auto* task = current && current->generation == identity.snapshot_generation
        ? find_script_run(*current, identity) : nullptr;
    const std::string unavailable = current
        ? current->generation == identity.snapshot_generation
            ? script_run_action_unavailable_reason(task, action)
            : "The immutable Task Center snapshot changed; reopen the run context"
        : "Task Center state is unavailable";
    if (!unavailable.empty()) {
        state().script_action_error = unavailable;
        return action_handler_result_t::failed(unavailable);
    }
    bool accepted = false;
    switch (action) {
    case script_run_action_t::cancel:
        accepted = task_center::request_cancel(identity.id);
        break;
    case script_run_action_t::retry:
        accepted = task_center::retry(identity.id);
        break;
    case script_run_action_t::focus:
        accepted = task_center::focus(identity.id);
        break;
    case script_run_action_t::open_log:
        accepted = task_center::open_log(identity.id);
        break;
    }
    state().script_action_error = accepted ? std::string{} :
        "Task Center rejected the action because the retained run state changed";
    return accepted ? action_handler_result_t::completed()
        : action_handler_result_t::failed(state().script_action_error);
}

bool contains_case_insensitive(std::string_view value, std::string_view query) {
    if (query.empty()) return true;
    return std::search(value.begin(), value.end(), query.begin(), query.end(),
        [](unsigned char left, unsigned char right) {
            return std::tolower(left) == std::tolower(right);
        }) != value.end();
}

std::string redacted_command(std::string value) {
    try {
        static const std::regex assignment(
            R"((password|passwd|token|secret|api[_-]?key|authorization)(\s*=\s*)("[^"]*"|'[^']*'|[^\s;&|]+))",
            std::regex_constants::icase | std::regex_constants::optimize);
        static const std::regex bearer(
            R"((bearer\s+)[A-Za-z0-9._~+/=-]+)",
            std::regex_constants::icase | std::regex_constants::optimize);
        static const std::regex option(
            R"(((?:--?)(?:password|passwd|token|secret|api[_-]?key|authorization)\s+)("[^"]*"|'[^']*'|[^\s;&|]+))",
            std::regex_constants::icase | std::regex_constants::optimize);
        value = std::regex_replace(value, assignment, "$1$2[redacted]");
        value = std::regex_replace(value, bearer, "$1[redacted]");
        value = std::regex_replace(value, option, "$1[redacted]");
    } catch (...) {
        return "Command metadata unavailable because secret-safe rendering failed";
    }
    return value;
}

int configuration_index(std::string_view id) {
    const auto& configurations = state().configurations;
    const auto found = std::find_if(configurations.begin(), configurations.end(),
        [&](const configuration_t& config) { return config.id == id; });
    return found == configurations.end() ? -1 :
        static_cast<int>(std::distance(configurations.begin(), found));
}

bool select_configuration(int index, bool persist_selection) {
    auto& store = state();
    if (index < 0 || index >= static_cast<int>(store.configurations.size())) return false;
    const std::string& next_id = store.configurations[static_cast<std::size_t>(index)].id;
    if (next_id == store.selected_id) return true;
    if (store.editor.dirty || store.editor.save_in_flight) {
        store.configuration_error = store.editor.save_in_flight
            ? "Wait for task configuration persistence before changing selection"
            : "Save or revert the edited configuration before changing selection";
        return false;
    }
    store.selected_id = next_id;
    store.editor.loaded = false;
    if (!persist_selection) return true;
    std::string error;
    if (!persist_user_configurations(error, false)) store.configuration_error = std::move(error);
    return true;
}

void open_selected_configuration_editor() {
    auto& store = state();
    const int index = configuration_index(store.selected_id);
    if (index < 0) {
        store.configuration_error = "Select a configuration to edit";
        return;
    }
    load_editor(index);
    store.configure_open = true;
}

void open_project_configuration_file() {
    auto& store = state();
    if (store.project_root.empty()) {
        store.configuration_error = "Open a code workspace before opening .aida/tasks.json";
        return;
    }
    const auto path = std::filesystem::path(store.project_root) / ".aida" / "tasks.json";
    file_browser::open_path(path.string());
    static_cast<void>(application_views::open_or_focus(stable_view_id_t("document.code")));
}

void retain_task_action_result(bool accepted, const char* failure) {
    state().script_action_error = accepted ? std::string{} : std::string(failure);
}

void retain_operation_result(operation_result_t result) {
    state().script_action_error = result.succeeded ? std::string{} : std::move(result.detail);
}

std::uint64_t fingerprint_append(std::uint64_t hash, std::string_view value) {
    for (const char character : value) {
        hash ^= static_cast<unsigned char>(character);
        hash *= 1099511628211ULL;
    }
    hash ^= 0xFFU;
    return hash * 1099511628211ULL;
}

std::uint64_t configuration_fingerprint(const configuration_t& configuration) {
    std::uint64_t hash = 1469598103934665603ULL;
    hash = fingerprint_append(hash, configuration.id);
    hash = fingerprint_append(hash, configuration.source_id);
    hash = fingerprint_append(hash, configuration.name);
    hash = fingerprint_append(hash, configuration.command);
    hash = fingerprint_append(hash, configuration.cwd);
    hash = fingerprint_append(hash, configuration.output_channel);
    hash = fingerprint_append(hash, configuration.problem_matcher);
    hash ^= static_cast<std::uint64_t>(configuration.kind) +
        (static_cast<std::uint64_t>(configuration.origin) << 8U);
    return hash == 0 ? 1 : hash;
}

std::uint64_t configuration_catalog_fingerprint() {
    std::uint64_t hash = fingerprint_append(1469598103934665603ULL,
        state().project_root);
    for (const auto& configuration : state().configurations) {
        hash ^= configuration_fingerprint(configuration) + 0x9E3779B97F4A7C15ULL +
            (hash << 6U) + (hash >> 2U);
    }
    return hash == 0 ? 1 : hash;
}

capability_state_t validate_configuration_identity(const configuration_t& retained,
    std::uint64_t generation, std::uint64_t catalog_fingerprint,
    const std::string& project_root) {
    auto& store = state();
    if (store.configuration_generation.load(std::memory_order_acquire) != generation ||
        store.project_root != project_root ||
        configuration_catalog_fingerprint() != catalog_fingerprint)
        return capability_state_t::unavailable(
            "The task configuration catalog or project scope changed; reopen the context menu");
    const int index = configuration_index(retained.id);
    if (index < 0)
        return capability_state_t::unavailable(
            "The retained task configuration was removed; reopen the context menu");
    const auto& current = store.configurations[static_cast<std::size_t>(index)];
    if (current.origin != retained.origin || current.source_id != retained.source_id ||
        configuration_fingerprint(current) != configuration_fingerprint(retained))
        return capability_state_t::unavailable(
            "The retained task configuration identity changed; reopen the context menu");
    return capability_state_t::available();
}

application_ui::retained_entity_action_t retained_script_action(const char* id,
    std::string unavailable, std::function<action_handler_result_t()> invoke) {
    application_ui::retained_entity_action_t action;
    action.action_id = id;
    action.capability = unavailable.empty() ? capability_state_t::available()
        : capability_state_t::unavailable(std::move(unavailable));
    action.invoke = std::move(invoke);
    return action;
}

void open_configuration_context(int index, context_menu_open_origin_t origin) {
    auto& store = state();
    if (index < 0 || index >= static_cast<int>(store.configurations.size())) return;
    const configuration_t retained = store.configurations[static_cast<std::size_t>(index)];
    const std::uint64_t generation = store.configuration_generation.load(
        std::memory_order_acquire);
    const std::uint64_t catalog_fingerprint = configuration_catalog_fingerprint();
    const std::string project_root = store.project_root;
    const auto validate = [retained, generation, catalog_fingerprint, project_root] {
        return validate_configuration_identity(retained, generation,
            catalog_fingerprint, project_root);
    };
    auto invoke_selected = [retained, validate](auto&& operation) {
        const auto current = validate();
        if (!current.enabled)
            return action_handler_result_t::failed(current.disabled_reason);
        const int retained_index = configuration_index(retained.id);
        if (!select_configuration(retained_index, false))
            return action_handler_result_t::failed(state().configuration_error.empty()
                ? "The retained task configuration could not be selected" : state().configuration_error);
        return operation(retained_index);
    };
    application_ui::retained_entity_context_t context;
    context.owner_id = "programming.scripts.configuration";
    context.entity_id = retained.id;
    context.entity_generation = generation ^ catalog_fingerprint;
    context.active_view = stable_view_id_t("view.ai.scripts");
    context.validate_identity = validate;
    std::string run_unavailable;
    if (store.configuration_loading)
        run_unavailable = "Programming configurations are loading";
    else if (store.editor.save_in_flight && store.selected_id != retained.id)
        run_unavailable = "Wait for task configuration persistence before changing selection";
    else if (store.editor.dirty && store.selected_id != retained.id)
        run_unavailable = "Save or revert the edited configuration before changing selection";
    else {
        std::unique_lock<std::mutex> lock(store.mutex, std::try_to_lock);
        if (!lock.owns_lock()) run_unavailable = "Programming task state is busy; try again";
        else {
            const auto active = store.active_runs.find(retained.id);
            if (active != store.active_runs.end() && active->second &&
                !active->second->terminal.load(std::memory_order_acquire))
                run_unavailable = "The retained configuration is already running";
        }
        if (run_unavailable.empty()) {
            std::string resolution_error;
            if (!resolve_configuration(retained, resolution_error))
                run_unavailable = std::move(resolution_error);
        }
    }
    context.actions.push_back(retained_script_action(
        "programming.configuration.run_review", run_unavailable,
        [invoke_selected] {
            return invoke_selected([](int) {
                const auto result = request_run_selected();
                return result.succeeded ? action_handler_result_t::completed()
                    : action_handler_result_t::failed(result.detail);
            });
        }));
    std::string edit_unavailable = retained.origin == configuration_origin_t::project &&
        project_root.empty() ? "Open a code workspace before opening .aida/tasks.json" : std::string{};
    if (edit_unavailable.empty() && store.editor.save_in_flight && store.selected_id != retained.id)
        edit_unavailable = "Wait for task configuration persistence before changing selection";
    if (edit_unavailable.empty() && store.editor.dirty && store.selected_id != retained.id)
        edit_unavailable = "Save or revert the edited configuration before changing selection";
    context.actions.push_back(retained_script_action(
        "programming.configuration.open_edit", edit_unavailable,
        [invoke_selected, retained] {
            return invoke_selected([retained](int retained_index) {
                if (retained.origin == configuration_origin_t::project) {
                    const auto path = std::filesystem::path(state().project_root) /
                        ".aida" / "tasks.json";
                    file_browser::open_path(path.string());
                    const auto opened = application_views::open_or_focus(
                        stable_view_id_t("document.code"));
                    return opened.ok() ? action_handler_result_t::completed()
                        : action_handler_result_t::failed(opened.detail);
                }
                load_editor(retained_index);
                state().configure_open = true;
                return action_handler_result_t::completed();
            });
        }));
    const std::size_t user_count = static_cast<std::size_t>(std::count_if(
        store.configurations.begin(), store.configurations.end(), [](const configuration_t& item) {
            return item.origin == configuration_origin_t::user;
        }));
    const std::string selection_unavailable = store.editor.save_in_flight &&
        store.selected_id != retained.id
        ? "Wait for task configuration persistence before changing selection"
        : store.editor.dirty && store.selected_id != retained.id
            ? "Save or revert the edited configuration before changing selection"
            : std::string{};
    context.actions.push_back(retained_script_action(
        "programming.configuration.duplicate", !selection_unavailable.empty()
            ? selection_unavailable : user_count >= 64
                ? "User task configurations reached the 64-entry bound" : std::string{},
        [invoke_selected] {
            return invoke_selected([](int retained_index) {
                const auto before = state().configurations.size();
                duplicate_configuration(retained_index);
                return state().configurations.size() == before + 1
                    ? action_handler_result_t::completed()
                    : action_handler_result_t::failed(state().configuration_error.empty()
                        ? "The retained configuration could not be duplicated"
                        : state().configuration_error);
            });
        }));
    std::string delete_unavailable = !selection_unavailable.empty()
        ? selection_unavailable : retained.origin == configuration_origin_t::user
            ? std::string{} : "Project task configurations must be edited in .aida/tasks.json";
    if (delete_unavailable.empty()) {
        std::unique_lock<std::mutex> lock(store.mutex, std::try_to_lock);
        if (!lock.owns_lock())
            delete_unavailable = "Programming task state is busy; try again";
        else {
            const auto active = store.active_runs.find(retained.id);
            if (active != store.active_runs.end() && active->second &&
                !active->second->terminal.load(std::memory_order_acquire))
                delete_unavailable = "Stop the retained configuration's active run before deleting it";
        }
    }
    context.actions.push_back(retained_script_action(
        "programming.configuration.delete_review", delete_unavailable,
        [invoke_selected, retained] {
            return invoke_selected([retained](int retained_index) {
                if (retained.origin != configuration_origin_t::user)
                    return action_handler_result_t::failed(
                        "Project task configurations cannot be deleted from user settings");
                load_editor(retained_index);
                state().editor.delete_requested = true;
                state().configure_open = true;
                return action_handler_result_t::completed();
            });
        }));
    application_ui::open_retained_entity_context_menu(std::move(context), origin);
}

void open_script_run_context(const task_center::task_snapshot_t& task,
                             std::uint64_t snapshot_generation,
                             context_menu_open_origin_t origin) {
    const script_run_identity_t identity = script_run_identity(task, snapshot_generation);
    application_ui::retained_entity_context_t context;
    context.owner_id = "programming.scripts.run";
    context.entity_id = task.id;
    context.entity_generation = snapshot_generation;
    context.active_view = stable_view_id_t("view.ai.scripts");
    context.validate_identity = [identity] {
        const auto current = task_center::snapshot();
        return current && current->generation == identity.snapshot_generation &&
                find_script_run(*current, identity)
            ? capability_state_t::available()
            : capability_state_t::unavailable(
                "The immutable Task Center snapshot or retained run identity changed; reopen the context menu");
    };
    const auto append = [&](const char* id, script_run_action_t action) {
        context.actions.push_back(retained_script_action(id,
            script_run_action_unavailable_reason(&task, action),
            [identity, action] { return invoke_script_run_action(identity, action); }));
    };
    append("programming.run.cancel", script_run_action_t::cancel);
    append("programming.run.retry_review", script_run_action_t::retry);
    append("programming.run.focus", script_run_action_t::focus);
    append("programming.run.open_log", script_run_action_t::open_log);
    application_ui::open_retained_entity_context_menu(std::move(context), origin);
}

void render_automation_scripts() {
    ensure_initialized();
    auto& store = state();
    ImGui::PushID("automation.scripts");
    ImGui::SetNextItemWidth((std::min)(320.0f,
        (std::max)(140.0f, ImGui::GetContentRegionAvail().x * 0.32f)));
    ImGui::InputTextWithHint("###aida.automation.scripts.filter", "Filter scripts...",
        store.scripts_filter.data(), store.scripts_filter.size());
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(aida::preview::semantics::register_last_item(
        "aida.automation.scripts.filter", "script-filter"));
#endif
    ImGui::SameLine();
    ImGui::BeginDisabled(store.configuration_loading || store.editor.save_in_flight);
    if (ImGui::SmallButton("New###aida.automation.scripts.new")) {
        add_user_configuration();
        store.configure_open = true;
    }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(aida::preview::semantics::register_last_item(
        "aida.automation.scripts.new", "script-action", false,
        store.configuration_loading || store.editor.save_in_flight));
#endif
    ImGui::SameLine();
    if (ImGui::SmallButton("Reload###aida.automation.scripts.reload")) {
        std::string error;
        if (!schedule_configuration_reload(true, error)) store.configuration_error = std::move(error);
    }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    static_cast<void>(aida::preview::semantics::register_last_item(
        "aida.automation.scripts.reload", "script-action", false,
        store.configuration_loading || store.editor.save_in_flight));
#endif
    ImGui::EndDisabled();
    if (store.configuration_loading) {
        ImGui::SameLine();
        ImGui::TextDisabled("Loading configurations...");
    }
    if (!store.configuration_error.empty()) {
        ImGui::TextColored(ImVec4(0.95f, 0.4f, 0.35f, 1.0f), "%s",
            store.configuration_error.c_str());
        ImGui::SameLine();
        if (ImGui::SmallButton("Retry load###aida.automation.scripts.retry_load")) {
            std::string error;
            if (!schedule_configuration_reload(true, error)) store.configuration_error = std::move(error);
        }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        static_cast<void>(aida::preview::semantics::register_last_item(
            "aida.automation.scripts.retry-load", "script-action"));
#endif
        if (!store.configurations.empty())
            ImGui::TextDisabled("The retained configuration snapshot may be stale.");
    }
    if (!store.script_action_error.empty())
        ImGui::TextColored(ImVec4(0.95f, 0.4f, 0.35f, 1.0f), "%s",
            store.script_action_error.c_str());
    const auto snapshot = task_center::snapshot();
    if (!snapshot) {
        ImGui::TextDisabled("Task state is loading...");
        ImGui::PopID();
        return;
    }

    std::vector<int> visible_configurations;
    visible_configurations.reserve(store.configurations.size());
    const std::string_view filter(store.scripts_filter.data());
    for (int index = 0; index < static_cast<int>(store.configurations.size()); ++index) {
        const auto& config = store.configurations[static_cast<std::size_t>(index)];
        if (contains_case_insensitive(config.name, filter) ||
            contains_case_insensitive(config.command, filter) ||
            contains_case_insensitive(kind_name(config.kind), filter))
            visible_configurations.push_back(index);
    }

    const bool compact = ImGui::GetContentRegionAvail().x < 760.0f;
    const float catalog_extent = compact ? (std::min)(210.0f,
        ImGui::GetContentRegionAvail().y * 0.36f) : (std::min)(310.0f,
        ImGui::GetContentRegionAvail().x * 0.34f);
    ImGui::BeginChild("###aida.automation.scripts.catalog",
        compact ? ImVec2(0.0f, catalog_extent) : ImVec2(catalog_extent, 0.0f), true);
    ImGui::BeginDisabled(store.configuration_loading);
    if (store.configuration_loading && store.configurations.empty()) {
        ImGui::TextDisabled("Awaiting configuration snapshot...");
    } else if (store.configurations.empty()) {
        ImGui::TextDisabled("No script configurations");
        ImGui::TextWrapped("Create a reviewed user configuration or add .aida/tasks.json to the open workspace.");
        if (ImGui::Button("Create Configuration###aida.automation.scripts.empty.create")) {
            add_user_configuration();
            store.configure_open = true;
        }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        static_cast<void>(aida::preview::semantics::register_last_item(
            "aida.automation.scripts.empty-create", "script-action", false,
            store.configuration_loading));
#endif
    } else if (visible_configurations.empty()) {
        ImGui::TextDisabled("No configurations match the filter");
    }
    int pending_duplicate_index = -1;
    int keyboard_focused_configuration = -1;
    for (const int index : visible_configurations) {
        const auto& config = store.configurations[static_cast<std::size_t>(index)];
        const bool selected = config.id == store.selected_id;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        const std::string semantic_token = aida::preview::semantics::entity_token(config.id);
#endif
        const std::string label = config.name + "###aida.automation.scripts.config." + config.id;
        if (ImGui::Selectable(label.c_str(), selected)) static_cast<void>(select_configuration(index, true));
        if (ImGui::IsItemFocused()) keyboard_focused_configuration = index;
        if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
            open_configuration_context(index, context_menu_open_origin_t::pointer);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        static_cast<void>(aida::preview::semantics::register_last_item(
            "aida.automation.scripts.config." + semantic_token, "script-configuration",
            false, store.configuration_loading));
#endif
        if (compact) {
            ImGui::SameLine();
            if (ImGui::SmallButton(("...###aida.automation.scripts.more." + config.id).c_str()))
                open_configuration_context(index, context_menu_open_origin_t::pointer);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            static_cast<void>(aida::preview::semantics::register_last_item(
                "aida.automation.scripts.more." + semantic_token, "script-context-action",
                false, store.configuration_loading));
#endif
        }
    }
    const bool configuration_menu_key = ImGui::IsKeyPressed(ImGuiKey_Menu, false);
    const bool configuration_shift_f10 = ImGui::GetIO().KeyShift &&
        ImGui::IsKeyPressed(ImGuiKey_F10, false);
    if (keyboard_focused_configuration >= 0 &&
        (configuration_menu_key || configuration_shift_f10))
        open_configuration_context(keyboard_focused_configuration,
            configuration_menu_key ? context_menu_open_origin_t::menu_key
                                   : context_menu_open_origin_t::shift_f10);
    ImGui::EndDisabled();
    application_ui::render_retained_entity_context_menu(
        "programming.scripts.configuration");
    ImGui::EndChild();
    if (!compact) ImGui::SameLine();

    ImGui::BeginChild("###aida.automation.scripts.detail", ImVec2(0.0f, 0.0f), false);
    const configuration_t* selected = selected_configuration();
    if (!selected) {
        ImGui::TextDisabled("Select a script configuration to inspect it");
    } else {
        ImGui::TextUnformatted(selected->name.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("%s / %s", kind_name(selected->kind).c_str(),
            selected->origin == configuration_origin_t::project ? "project" : "user");
        const std::string unavailable = run_unavailable_reason();
        ImGui::BeginDisabled(!unavailable.empty());
        if (ImGui::Button("Run with Review...###aida.automation.scripts.run"))
            retain_operation_result(request_run_selected());
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        static_cast<void>(aida::preview::semantics::register_last_item(
            "aida.automation.scripts.run", "script-action", false, !unavailable.empty()));
#endif
        ImGui::EndDisabled();
        design::tooltip_for_last_item(unavailable.empty()
            ? "Resolve and review the exact process command before execution" : unavailable.c_str());
        ImGui::SameLine();
        if (ImGui::Button(selected->origin == configuration_origin_t::project
                ? "Open Source###aida.automation.scripts.edit"
                : "Edit...###aida.automation.scripts.edit")) {
            if (selected->origin == configuration_origin_t::project) open_project_configuration_file();
            else open_selected_configuration_editor();
        }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        static_cast<void>(aida::preview::semantics::register_last_item(
            "aida.automation.scripts.edit", "script-action"));
#endif
        ImGui::SameLine();
        if (ImGui::Button("Duplicate...###aida.automation.scripts.duplicate"))
            pending_duplicate_index = configuration_index(selected->id);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        static_cast<void>(aida::preview::semantics::register_last_item(
            "aida.automation.scripts.duplicate", "script-action"));
#endif
        ImGui::Separator();
        ImGui::Text("Source: %s", selected->origin == configuration_origin_t::project
            ? ".aida/tasks.json" : "User settings");
        ImGui::Text("Scope: %s", store.project_root.empty()
            ? "No workspace" : store.project_root.c_str());
        const std::string command = redacted_command(selected->command);
        ImGui::TextWrapped("Command: %s", command.c_str());
        ImGui::TextWrapped("Arguments: included in the reviewed command line; secret-like values are redacted here");
        ImGui::TextWrapped("Working directory: %s", selected->cwd.empty()
            ? "Inherited from AiDA" : selected->cwd.c_str());
        ImGui::Text("Output: %s", selected->output_channel.empty()
            ? selected->name.c_str() : selected->output_channel.c_str());
        ImGui::Text("Problem matcher: %s", selected->problem_matcher.c_str());
        ImGui::TextWrapped("Environment: inherited by the canonical executor; credentials are never expanded in this catalog");
        ImGui::TextDisabled("Execution is approval-gated and runs outside the debugger in a cancellable process job.");
    }
    if (pending_duplicate_index >= 0) duplicate_configuration(pending_duplicate_index);

    ImGui::Spacing();
    ImGui::SeparatorText("Runs");
    std::vector<const task_center::task_snapshot_t*> tasks;
    tasks.reserve(snapshot->tasks.size());
    for (auto it = snapshot->tasks.rbegin(); it != snapshot->tasks.rend(); ++it)
        if (it->source == "programming.config") tasks.push_back(&*it);
    std::optional<script_run_identity_t> pointer_context_run;
    std::optional<script_run_identity_t> keyboard_focused_run;
    if (tasks.empty()) {
        ImGui::TextDisabled("No script runs in this session");
    } else if (ImGui::BeginTable("###aida.automation.scripts.runs", 4,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
            ImVec2(0.0f, (std::max)(130.0f, ImGui::GetContentRegionAvail().y)))) {
        ImGui::TableSetupColumn("Script", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 92.f);
        ImGui::TableSetupColumn("Stage", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 128.f);
        ImGui::TableHeadersRow();
        const float row_height = ImGui::GetTextLineHeightWithSpacing() * 3.0f;
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(tasks.size()), row_height);
        while (clipper.Step()) for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& task = *tasks[static_cast<std::size_t>(row)];
            const script_run_identity_t identity = script_run_identity(task, snapshot->generation);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            const std::string task_token = aida::preview::semantics::entity_token(task.id);
#endif
            ImGui::PushID(task.id.c_str());
            ImGui::TableNextRow(ImGuiTableRowFlags_None, row_height);
            ImGui::TableSetColumnIndex(0);
            const bool selected = store.selected_script_run &&
                same_script_run(task, *store.selected_script_run);
            ImGui::Selectable("###run-row", selected,
                ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                ImVec2(0.0f, row_height));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            static_cast<void>(aida::preview::semantics::register_last_item(
                "aida.automation.scripts.run." + task_token, "script-run"));
#endif
            if (ImGui::IsItemFocused()) {
                store.selected_script_run = identity;
                keyboard_focused_run = identity;
            }
            if (ImGui::IsItemActivated() || ImGui::IsItemClicked(ImGuiMouseButton_Left))
                store.selected_script_run = identity;
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                store.selected_script_run = identity;
                pointer_context_run = identity;
            }
            ImGui::SameLine(0.0f, 0.0f);
            ImGui::TextUnformatted(task.label.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(task_state_label(task.state));
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(task.stage.c_str());
            if (ImGui::IsItemHovered() && !task.stage.empty())
                ImGui::SetTooltip("%s", task.stage.c_str());
            if (!task.result_summary.empty()) ImGui::TextDisabled("%s", task.result_summary.c_str());
            if (task.progress >= 0.0f) ImGui::ProgressBar(task.progress, ImVec2(-1.0f, 0.0f));
            ImGui::TableSetColumnIndex(3);
            bool previous_action = false;
            const std::string cancel_unavailable = script_run_action_unavailable_reason(
                &task, script_run_action_t::cancel);
            if (cancel_unavailable.empty() && ImGui::SmallButton("Cancel"))
                invoke_script_run_action(identity, script_run_action_t::cancel);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            if (cancel_unavailable.empty()) static_cast<void>(aida::preview::semantics::register_last_item(
                "aida.automation.scripts.run-cancel." + task_token, "script-run-action"));
#endif
            previous_action = cancel_unavailable.empty();
            const std::string retry_unavailable = script_run_action_unavailable_reason(
                &task, script_run_action_t::retry);
            if (retry_unavailable.empty()) {
                if (previous_action) ImGui::SameLine();
                if (ImGui::SmallButton("Retry"))
                    invoke_script_run_action(identity, script_run_action_t::retry);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                static_cast<void>(aida::preview::semantics::register_last_item(
                    "aida.automation.scripts.run-retry." + task_token, "script-run-action"));
#endif
                previous_action = true;
            }
            const std::string focus_unavailable = script_run_action_unavailable_reason(
                &task, script_run_action_t::focus);
            if (focus_unavailable.empty()) {
                if (previous_action) ImGui::SameLine();
                if (ImGui::SmallButton("Focus"))
                    invoke_script_run_action(identity, script_run_action_t::focus);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                static_cast<void>(aida::preview::semantics::register_last_item(
                    "aida.automation.scripts.run-focus." + task_token, "script-run-action"));
#endif
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (pointer_context_run) {
        const auto* retained = find_script_run(*snapshot, *pointer_context_run);
        if (retained)
            open_script_run_context(*retained, snapshot->generation,
                context_menu_open_origin_t::pointer);
    }
    const bool run_menu_key = ImGui::IsKeyPressed(ImGuiKey_Menu, false);
    const bool run_shift_f10 = ImGui::GetIO().KeyShift &&
        ImGui::IsKeyPressed(ImGuiKey_F10, false);
    if (keyboard_focused_run && (run_menu_key || run_shift_f10)) {
        store.selected_script_run = *keyboard_focused_run;
        const auto* retained = find_script_run(*snapshot, *keyboard_focused_run);
        if (retained)
            open_script_run_context(*retained, snapshot->generation,
                run_menu_key ? context_menu_open_origin_t::menu_key
                             : context_menu_open_origin_t::shift_f10);
    }
    application_ui::render_retained_entity_context_menu("programming.scripts.run");
    ImGui::EndChild();
    ImGui::PopID();
}

void render_modals() {
    ensure_initialized();
    auto& store = state();
    if (store.configure_open) {
        design::open_dialog("programming.task.configurations",
            "Programming Task Configurations");
        store.configure_open = false;
    }
    if (design::begin_dialog("programming.task.configurations",
            "Programming Task Configurations", ImVec2(860.0f, 540.0f),
            ImVec2(620.0f, 420.0f))) {
        const bool can_close = !store.editor.dirty && !store.editor.save_in_flight;
        const float footer_height = design::dialog_footer_reserve_height(
            "Close", nullptr);
        design::begin_dialog_body("programming_task_configurations_body",
            footer_height);
        ImGui::TextUnformatted("Explicit Programming Tasks and Launches");
        ImGui::TextDisabled("AiDA runs only configurations you define here or in .aida/tasks.json. This does not invoke RE Run Target.");
        ImGui::Separator();
        ImGui::BeginDisabled(store.configuration_loading);
        render_configuration_editor();
        ImGui::EndDisabled();
        ImGui::Separator();
        if (ImGui::Button("Reload User and Project Configurations")) {
            std::string error;
            if (!schedule_configuration_reload(true, error)) store.configuration_error = std::move(error);
        }
        if (!can_close)
            ImGui::TextDisabled("Save, revert, or delete the edited user configuration before closing.");
        design::end_dialog_body();
        const auto footer = design::dialog_footer(
            "programming_task_configurations_footer", "Close",
            can_close, false, nullptr);
        if ((footer.confirmed || footer.cancelled) && can_close)
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
    if (store.run_review_open && store.pending_run) {
        design::open_dialog("programming.task.run.review",
            "Review Programming Run");
        store.run_review_open = false;
    }
    if (design::begin_dialog("programming.task.run.review",
            "Review Programming Run", ImVec2(680.0f, 390.0f),
            ImVec2(500.0f, 320.0f))) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        const bool can_run = false;
#else
        const bool can_run = static_cast<bool>(store.pending_run);
#endif
        const float footer_height = design::dialog_footer_reserve_height(
            "Run", "Cancel");
        design::begin_dialog_body("programming_task_run_review_body",
            footer_height);
        if (!store.pending_run) {
            ImGui::TextUnformatted("The selected configuration is no longer available.");
        } else {
            const auto& pending = *store.pending_run;
            ImGui::Text("%s: %s", pending.source.kind == configuration_kind_t::launch
                ? "Launch" : pending.source.kind == configuration_kind_t::test ? "Test" : "Task",
                pending.source.name.c_str());
            ImGui::Separator();
            ImGui::TextWrapped("Command: %s", pending.command.c_str());
            ImGui::TextWrapped("Working directory: %s", pending.cwd.empty() ? "Inherited from AiDA" : pending.cwd.c_str());
            ImGui::Text("Output channel: %s", pending.channel.c_str());
            ImGui::Text("Problem matcher: %s", pending.source.problem_matcher.c_str());
            ImGui::TextDisabled("The process and its descendants run outside AiDA's debugger. Cancel/close terminates the complete process tree. This is separate from RE Run Target.");
            if (!store.configuration_error.empty())
                ImGui::TextColored(ImVec4(0.95f, 0.4f, 0.35f, 1.0f), "%s",
                    store.configuration_error.c_str());
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            ImGui::TextColored(ImVec4(0.95f, 0.65f, 0.25f, 1.0f),
                "External process execution is disabled in the Studio compatibility runtime.");
#endif
        }
        design::end_dialog_body();
        const auto footer = design::dialog_footer(
            "programming_task_run_review_footer", "Run", can_run, false);
        if (footer.confirmed && store.pending_run) {
            const auto pending = *store.pending_run;
            const auto result = start_run(pending);
            if (result.succeeded) {
                store.pending_run.reset();
                ImGui::CloseCurrentPopup();
            } else {
                store.configuration_error = result.detail;
            }
        } else if (footer.cancelled) {
            store.pending_run.reset();
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

bool output_line_visible(std::string_view line) {
    ensure_initialized();
    const std::string channel = state().selected_channel;
    if (channel.empty()) return true;
    const std::string prefix = channel_prefix(channel);
    return line.size() >= prefix.size() && line.compare(0, prefix.size(), prefix) == 0;
}

std::string selected_output_channel() {
    ensure_initialized();
    return state().selected_channel;
}

operation_result_t request_run_selected() {
    const configuration_t* config = selected_configuration();
    if (!config) return {false, run_unavailable_reason()};
    {
        std::unique_lock<std::mutex> lock(state().mutex, std::try_to_lock);
        if (!lock.owns_lock())
            return {false, "Programming task state is busy; try again"};
        const auto active = state().active_runs.find(config->id);
        if (active != state().active_runs.end()) {
            if (active->second && !active->second->terminal.load(std::memory_order_acquire))
                return {false, "The selected configuration is already running"};
            state().active_runs.erase(active);
            state().active_count.store(state().active_runs.size(), std::memory_order_release);
        }
    }
    std::string error;
    auto resolved = resolve_configuration(*config, error);
    if (!resolved) return {false, error};
    state().configuration_error.clear();
    state().pending_run = std::move(*resolved);
    state().run_review_open = true;
    static_cast<void>(application_views::open_or_focus(stable_view_id_t("view.output")));
    return {true, {}};
}

operation_result_t request_run_selected_for_file(const std::string& path, bool launch) {
    const configuration_kind_t required = launch
        ? configuration_kind_t::launch : configuration_kind_t::task;
    const std::string unavailable = file_run_unavailable_reason(path, required);
    if (!unavailable.empty()) return {false, unavailable};
    const configuration_t* config = selected_configuration();
    if (!config) return {false, launch
        ? "Select an explicit Launch configuration before debugging this file"
        : "Select an explicit Task configuration before running this file"};
    std::string error;
    auto resolved = resolve_configuration(*config, error, path);
    if (!resolved) return {false, error};
    state().configuration_error.clear();
    state().pending_run = std::move(*resolved);
    state().run_review_open = true;
    static_cast<void>(application_views::open_or_focus(stable_view_id_t("view.output")));
    return {true, {}};
}

operation_result_t request_test_selected_for_file(const std::string& path) {
    const std::string unavailable = file_run_unavailable_reason(
        path, configuration_kind_t::test);
    if (!unavailable.empty()) return {false, unavailable};
    const configuration_t* config = selected_configuration();
    if (!config)
        return {false, "Select an explicit Test configuration before testing this file"};
    std::string error;
    auto resolved = resolve_configuration(*config, error, path);
    if (!resolved) return {false, error};
    state().configuration_error.clear();
    state().pending_run = std::move(*resolved);
    state().run_review_open = true;
    static_cast<void>(application_views::open_or_focus(stable_view_id_t("view.output")));
    return {true, {}};
}

operation_result_t request_cancel_active() {
    ensure_initialized();
    std::shared_ptr<run_state_t> target;
    const configuration_t* selected = selected_configuration();
    {
        std::unique_lock<std::mutex> lock(state().mutex, std::try_to_lock);
        if (!lock.owns_lock())
            return {false, "Programming task state is busy; try again"};
        if (selected) {
            const auto found = state().active_runs.find(selected->id);
            if (found != state().active_runs.end() && found->second &&
                !found->second->terminal.load(std::memory_order_acquire)) target = found->second;
        }
        if (!target) {
            for (const auto& [id, candidate] : state().active_runs) {
                static_cast<void>(id);
                if (!candidate || candidate->terminal.load(std::memory_order_acquire)) continue;
                if (target) {
                    target.reset();
                    break;
                }
                target = candidate;
            }
        }
    }
    if (!target) return {false, cancel_unavailable_reason()};
    return task_center::request_cancel(target->id)
        ? operation_result_t{true, {}}
        : operation_result_t{false, "The Task Center did not accept cancellation"};
}

operation_result_t request_retry_last() {
    ensure_initialized();
    std::shared_ptr<run_state_t> run;
    {
        std::unique_lock<std::mutex> lock(state().mutex, std::try_to_lock);
        if (!lock.owns_lock())
            return {false, "Programming task state is busy; try again"};
        run = state().last_run;
    }
    if (!run || !run->terminal.load(std::memory_order_acquire))
        return {false, retry_unavailable_reason()};
    const auto found = std::find_if(state().configurations.begin(), state().configurations.end(),
        [&](const configuration_t& config) { return config.id == run->configuration.source.id; });
    if (found == state().configurations.end())
        return {false, "The configuration used by the last run no longer exists"};
    state().selected_id = found->id;
    state().editor.loaded = false;
    std::string persistence_error;
    if (!persist_user_configurations(persistence_error, false))
        state().configuration_error = std::move(persistence_error);
    return request_run_selected();
}

operation_result_t open_configurations() {
    ensure_initialized();
    state().configure_open = true;
    static_cast<void>(application_views::open_or_focus(stable_view_id_t("view.output")));
    return {true, {}};
}

operation_result_t reload_configurations() {
    ensure_initialized();
    std::string error;
    if (!schedule_configuration_reload(true, error)) {
        state().configuration_error = error;
        return {false, error};
    }
    return {true, {}};
}

bool has_active_run() {
    ensure_initialized();
    return state().active_count.load(std::memory_order_acquire) != 0;
}

std::size_t problem_count() {
    ensure_initialized();
    return state().retained_problem_count.load(std::memory_order_acquire);
}

std::string run_unavailable_reason() {
    ensure_initialized();
    if (state().configuration_loading) return "Programming configurations are loading";
    if (state().configurations.empty())
        return "Define an explicit user configuration or add .aida/tasks.json to the open folder";
    const auto config = selected_configuration();
    if (!config) return "Select a programming task or launch configuration";
    std::unique_lock<std::mutex> lock(state().mutex, std::try_to_lock);
    if (!lock.owns_lock()) return "Programming task state is busy; try again";
    const auto active = state().active_runs.find(config->id);
    if (active != state().active_runs.end() && active->second &&
        !active->second->terminal.load(std::memory_order_acquire))
        return "The selected configuration is already running";
    return {};
}

std::string run_for_file_unavailable_reason(const std::string& path, bool launch) {
    return file_run_unavailable_reason(path, launch
        ? configuration_kind_t::launch : configuration_kind_t::task);
}

std::string test_for_file_unavailable_reason(const std::string& path) {
    return file_run_unavailable_reason(path, configuration_kind_t::test);
}

std::string cancel_unavailable_reason() {
    ensure_initialized();
    const configuration_t* selected = selected_configuration();
    std::unique_lock<std::mutex> lock(state().mutex, std::try_to_lock);
    if (!lock.owns_lock()) return "Programming task state is busy; try again";
    std::size_t active_count = 0;
    bool selected_active = false;
    for (const auto& [id, run] : state().active_runs) {
        if (!run || run->terminal.load(std::memory_order_acquire)) continue;
        ++active_count;
        if (selected && selected->id == id) selected_active = true;
    }
    if (active_count == 0) return "There is no active programming task or launch";
    if (active_count == 1 || selected_active) return {};
    return "Select one of the running configurations before requesting cancellation";
}

std::string retry_unavailable_reason() {
    ensure_initialized();
    std::unique_lock<std::mutex> lock(state().mutex, std::try_to_lock);
    if (!lock.owns_lock()) return "Programming task state is busy; try again";
    if (!state().last_run || !state().last_run->terminal.load(std::memory_order_acquire))
        return "There is no completed programming run to retry";
    const auto active = state().active_runs.find(state().last_run->configuration.source.id);
    if (active != state().active_runs.end() && active->second &&
        !active->second->terminal.load(std::memory_order_acquire))
        return "The last run's configuration is already active";
    return {};
}

}
