#include "programming_tasks.hpp"

#include "application_view_registry.hpp"
#include "application_ui_runtime.hpp"
#include "design_system.hpp"
#include "task_center.hpp"
#include "ui_thread_dispatcher.hpp"
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

enum class configuration_kind_t : std::uint8_t { task, launch };
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

struct state_t {
    std::vector<configuration_t> configurations;
    std::string project_root;
    std::string configuration_error;
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
    return value == configuration_kind_t::launch ? "launch" : "task";
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

std::string file_run_unavailable_reason(const std::string& path, bool launch) {
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
    if (!config)
        return launch
            ? "Select an explicit Launch configuration before debugging this file"
            : "Select an explicit Task configuration before running this file";
    const configuration_kind_t required = launch
        ? configuration_kind_t::launch : configuration_kind_t::task;
    if (config->kind != required)
        return launch
            ? "The selected programming configuration is a Task; select a Launch configuration"
            : "The selected programming configuration is a Launch; select a Task configuration";
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
    if (kind != "task" && kind != "launch") {
        error = "Configuration kind must be task or launch";
        return false;
    }
    result.kind = kind == "launch" ? configuration_kind_t::launch : configuration_kind_t::task;
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
        ? "Programming Launch" : "Programming Task";
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
    editor.kind = config.kind == configuration_kind_t::launch ? 1 : 0;
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
    config.kind = editor.kind == 1 ? configuration_kind_t::launch : configuration_kind_t::task;
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
    const char* kinds[] = {"Task", "Launch"};
    editor.dirty |= ImGui::Combo("Kind", &editor.kind, kinds, 2);
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
    if (editor.delete_requested) ImGui::OpenPopup("Delete Task Configuration");
    if (ImGui::BeginPopupModal("Delete Task Configuration", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("Delete this user task configuration?");
        ImGui::TextDisabled("This removes only the saved configuration. Existing output and diagnostics remain.");
        if (ImGui::Button("Delete", ImVec2(110.0f, 0.0f))) {
            delete_selected_configuration();
            editor.delete_requested = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(110.0f, 0.0f))) {
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
    const std::string run_reason = run_unavailable_reason();
    ImGui::BeginDisabled(!run_reason.empty());
    if (ImGui::SmallButton("Run..."))
        static_cast<void>(application_ui::execute_output_action(static_cast<int>(bottom_tab_t::output),
            "programming.task.run", action_invocation_source_t::toolbar));
    ImGui::EndDisabled();
    if (!run_reason.empty() && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("%s", run_reason.c_str());
    ImGui::SameLine();
    if (ImGui::SmallButton("Configure..."))
        static_cast<void>(application_ui::execute_output_action(static_cast<int>(bottom_tab_t::output),
            "programming.task.configure", action_invocation_source_t::toolbar));
    if (has_active_run()) {
        ImGui::SameLine();
        const std::string cancel_reason = cancel_unavailable_reason();
        ImGui::BeginDisabled(!cancel_reason.empty());
        if (ImGui::SmallButton("Cancel"))
            static_cast<void>(application_ui::execute_output_action(static_cast<int>(bottom_tab_t::output),
                "programming.task.cancel", action_invocation_source_t::toolbar));
        ImGui::EndDisabled();
        if (!cancel_reason.empty() && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("%s", cancel_reason.c_str());
    }
    const std::size_t problems = problem_count();
    if (problems != 0) {
        ImGui::SameLine();
        const std::string label = "Problems (" + std::to_string(problems) + ")";
        if (ImGui::SmallButton(label.c_str()))
            static_cast<void>(application_ui::execute_output_action(static_cast<int>(bottom_tab_t::output),
                "programming.show_problems", action_invocation_source_t::toolbar));
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

void render_modals() {
    ensure_initialized();
    auto& store = state();
    if (store.configure_open) {
        ImGui::OpenPopup("Programming Task Configurations");
        store.configure_open = false;
    }
    const ImVec2 work = ImGui::GetMainViewport()->WorkSize;
    ImGui::SetNextWindowSize(ImVec2((std::min)(860.0f, work.x * 0.94f),
        (std::min)(540.0f, work.y * 0.9f)), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal("Programming Task Configurations", nullptr,
            ImGuiWindowFlags_NoSavedSettings)) {
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
        ImGui::SameLine();
        ImGui::BeginDisabled(store.editor.dirty || store.editor.save_in_flight);
        if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
        ImGui::EndDisabled();
        if ((store.editor.dirty || store.editor.save_in_flight) &&
            ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Save or delete the edited user configuration before closing");
        ImGui::EndPopup();
    }
    if (store.run_review_open && store.pending_run) {
        ImGui::OpenPopup("Review Programming Run");
        store.run_review_open = false;
    }
    ImGui::SetNextWindowSize(ImVec2((std::min)(680.0f, work.x * 0.94f), 0.0f), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal("Review Programming Run", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
        if (!store.pending_run) {
            ImGui::TextUnformatted("The selected configuration is no longer available.");
        } else {
            const auto& pending = *store.pending_run;
            ImGui::Text("%s: %s", pending.source.kind == configuration_kind_t::launch ? "Launch" : "Task",
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
            ImGui::BeginDisabled();
#endif
            if (ImGui::Button("Run", ImVec2(120.0f, 0.0f))) {
                const auto result = start_run(pending);
                if (result.succeeded) {
                    store.pending_run.reset();
                    ImGui::CloseCurrentPopup();
                } else {
                    store.configuration_error = result.detail;
                }
            }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            ImGui::EndDisabled();
#endif
            ImGui::SameLine();
            if (ImGui::Button("Cancel", ImVec2(120.0f, 0.0f))) {
                store.pending_run.reset();
                ImGui::CloseCurrentPopup();
            }
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
    const std::string unavailable = file_run_unavailable_reason(path, launch);
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
    return file_run_unavailable_reason(path, launch);
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
