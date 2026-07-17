#include "explorer_views.hpp"

#include "application_view_registry.hpp"
#include "application_ui_runtime.hpp"
#include "design_system.hpp"
#include "output_views.hpp"
#include "task_center.hpp"
#include "theme.hpp"
#include "ui_thread_dispatcher.hpp"
#include "workspace_layout.hpp"
#include "../../helpers/globals.h"
#include "../../helpers/helpers.h"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#else
#include "../analysis/workspace_search.hpp"
#endif
#include "../session/analysis_session.hpp"
#include "../settings/standalone_settings.hpp"
#include "../infra/executor.hpp"

#include "imgui/imgui.h"
#include "ide_icons.h"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <Windows.h>
#include <shellapi.h>
#endif

namespace aida::ui::explorer_views {
namespace {

std::string path_key(const std::string& path);

std::filesystem::path path_from_utf8(const std::string& value) {
#if defined(__cpp_char8_t)
    const auto* begin = reinterpret_cast<const char8_t*>(value.data());
    return std::filesystem::path(std::u8string(begin, begin + value.size()));
#else
    return std::filesystem::u8path(value);
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

struct explorer_presentation_state_t {
    char filter[256] = {};
    std::string applied_filter;
    std::string indexed_root;
    std::size_t indexed_entry_count = 0;
    bool filter_dirty = true;
    std::vector<int> visible_indices;
};

explorer_presentation_state_t& explorer_presentation() {
    static explorer_presentation_state_t value;
    return value;
}

struct file_operation_state_t {
    file_operation_t operation = file_operation_t::new_file;
    std::string source;
    std::string clipboard_path;
    std::vector<file_operation_target_t> sources;
    std::vector<file_operation_target_t> clipboard_targets;
    bool source_directory = false;
    bool clipboard_directory = false;
    bool clipboard_cut = false;
    bool name_dialog_open = false;
    bool delete_dialog_open = false;
    bool name_dialog_requested = false;
    bool delete_dialog_requested = false;
    bool operation_pending = false;
    std::uint64_t generation = 0;
    std::uint64_t task_id = 0;
    std::shared_ptr<std::atomic<bool>> dispatch_failed;
    char name[260] = {};
    std::string validation_error;
    std::string operation_error;
};

file_operation_state_t& file_operations() {
    static file_operation_state_t value;
    return value;
}

bool path_inside_roots(const std::filesystem::path& candidate,
    const std::vector<std::string>& roots, bool allow_root) {
    const std::string key = path_key(path_to_utf8(candidate.lexically_normal()));
    if (key.empty())
        return false;
    for (const auto& root_value : roots) {
        const std::string root = path_key(root_value);
        if (root.empty())
            continue;
        if (key == root)
            return allow_root;
        if (key.size() > root.size() && key.compare(0, root.size(), root) == 0 &&
            (key[root.size()] == '/' || key[root.size()] == '\\'))
            return true;
    }
    return false;
}

bool path_inside_root(const std::filesystem::path& candidate, bool allow_root) {
    return path_inside_roots(candidate, file_browser::roots, allow_root);
}

bool valid_leaf_name(const std::string& value, std::string& reason) {
    if (value.empty()) {
        reason = "Enter a name";
        return false;
    }
    if (value == "." || value == "..") {
        reason = "The name cannot be '.' or '..'";
        return false;
    }
    if (value.size() > 240) {
        reason = "The name exceeds the 240-byte workspace limit";
        return false;
    }
    constexpr const char* invalid = "<>:\"/\\|?*";
    for (const char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if (byte < 0x20 || std::strchr(invalid, static_cast<int>(byte))) {
            reason = "The name contains a control character or a Windows-reserved character";
            return false;
        }
    }
    if (value.back() == ' ' || value.back() == '.') {
        reason = "Windows file names cannot end with a space or period";
        return false;
    }
    std::string device = value.substr(0, value.find('.'));
    std::transform(device.begin(), device.end(), device.begin(),
        [](unsigned char character) { return static_cast<char>(std::toupper(character)); });
    const bool numbered_device = device.size() == 4 &&
        (device.compare(0, 3, "COM") == 0 || device.compare(0, 3, "LPT") == 0) &&
        device[3] >= '1' && device[3] <= '9';
    if (device == "CON" || device == "PRN" || device == "AUX" ||
        device == "NUL" || numbered_device) {
        reason = "The name is reserved by Windows";
        return false;
    }
    reason.clear();
    return true;
}

const char* operation_label(file_operation_t operation) {
    switch (operation) {
    case file_operation_t::new_file: return "Create file";
    case file_operation_t::new_folder: return "Create folder";
    case file_operation_t::rename: return "Rename item";
    case file_operation_t::cut: return "Cut item";
    case file_operation_t::copy: return "Copy item";
    case file_operation_t::paste: return "Paste item";
    case file_operation_t::duplicate: return "Duplicate item";
    case file_operation_t::remove: return "Delete item";
    case file_operation_t::open_with: return "Open with";
    case file_operation_t::terminal_here: return "Open terminal here";
    }
    return "Workspace operation";
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
bool bounded_copy_tree(const std::filesystem::path& source,
    const std::filesystem::path& destination,
    const std::shared_ptr<std::atomic<bool>>& cancelled, std::string& detail,
    std::uint64_t& total_bytes, std::size_t& entry_count) {
    namespace fs = std::filesystem;
    constexpr std::uint64_t maximum_bytes = 1024ULL * 1024ULL * 1024ULL;
    constexpr std::size_t maximum_entries = 100000;
    std::error_code error;
    if (fs::exists(destination, error) || error) {
        detail = error ? error.message() : "The destination already exists";
        return false;
    }
    if (fs::is_regular_file(source, error)) {
        if (error) {
            detail = error.message();
            return false;
        }
        const auto size = fs::file_size(source, error);
        if (error || size > maximum_bytes - total_bytes || entry_count >= maximum_entries) {
            detail = error ? error.message() : "The file exceeds the 1 GiB duplicate limit";
            return false;
        }
        if (!fs::copy_file(source, destination, fs::copy_options::none, error)) {
            detail = error ? error.message() : "The file copy did not complete";
            return false;
        }
        total_bytes += size;
        ++entry_count;
        return true;
    }
    if (!fs::is_directory(source, error) || error) {
        detail = error ? error.message() : "The source is not a regular file or directory";
        return false;
    }
    fs::create_directory(destination, error);
    if (error) {
        detail = error.message();
        return false;
    }
    if (++entry_count > maximum_entries) {
        detail = "The selection exceeds the 100,000-entry copy limit";
        std::error_code cleanup_error;
        fs::remove_all(destination, cleanup_error);
        return false;
    }
    for (fs::recursive_directory_iterator iterator(source,
            fs::directory_options::skip_permission_denied, error), end;
         iterator != end && !error; iterator.increment(error)) {
        if (cancelled->load(std::memory_order_acquire)) {
            detail = "The copy was cancelled";
            error = std::make_error_code(std::errc::operation_canceled);
            break;
        }
        if (++entry_count > maximum_entries) {
            detail = "The directory exceeds the 100,000-entry duplicate limit";
            error = std::make_error_code(std::errc::file_too_large);
            break;
        }
        const fs::path relative = iterator->path().lexically_relative(source);
        const fs::path target = destination / relative;
        if (iterator->is_symlink(error) || iterator->is_other(error)) {
            detail = "Workspace copies reject symbolic links and special filesystem entries";
            error = std::make_error_code(std::errc::operation_not_supported);
            break;
        }
        if (iterator->is_directory(error)) {
            fs::create_directory(target, error);
        } else if (iterator->is_regular_file(error)) {
            const auto size = iterator->file_size(error);
            if (!error && (size > maximum_bytes - total_bytes)) {
                detail = "The directory exceeds the 1 GiB duplicate limit";
                error = std::make_error_code(std::errc::file_too_large);
                break;
            }
            if (!error) {
                total_bytes += size;
                fs::copy_file(iterator->path(), target, fs::copy_options::none, error);
            }
        }
    }
    if (error) {
        if (detail.empty())
            detail = error.message();
        std::error_code cleanup_error;
        fs::remove_all(destination, cleanup_error);
        return false;
    }
    return true;
}
#endif

file_operation_result_t submit_file_operation(file_operation_t operation,
    std::filesystem::path source, std::filesystem::path destination,
    bool source_directory) {
    auto& state = file_operations();
    if (state.operation_pending)
        return {false, "Another Project Explorer filesystem operation is already running"};
    const bool source_may_be_root = operation == file_operation_t::new_file ||
        operation == file_operation_t::new_folder;
    if (!path_inside_root(source, source_may_be_root))
        return {false, "The source is outside the open Project Explorer roots"};
    if (!destination.empty() && !path_inside_root(destination, false))
        return {false, "The destination is outside the open Project Explorer roots"};
    state.operation_pending = true;
    state.operation_error.clear();
    const std::uint64_t generation = ++state.generation;
    const std::vector<std::string> roots = file_browser::roots;
    auto cancelled = std::make_shared<std::atomic<bool>>(false);
    auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
    state.dispatch_failed = dispatch_failed;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "project_explorer";
    submission.label = "project_explorer.file_operation";
    submission.thread_class = "bounded_filesystem_io";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 3;
    submission.generation = generation;
    submission.cancel_hook = [cancelled] {
        cancelled->store(true, std::memory_order_release);
    };
    submission.body = [operation, source = std::move(source), destination = std::move(destination),
            roots, source_directory, cancelled, dispatch_failed, generation]() mutable {
        bool succeeded = false;
        std::string detail;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(operation);
        static_cast<void>(source_directory);
        succeeded = !cancelled->load(std::memory_order_acquire);
        detail = succeeded ? "Preview filesystem operation completed deterministically" :
            "The preview filesystem operation was cancelled";
#else
        namespace fs = std::filesystem;
        try {
            std::error_code error;
            const fs::file_status source_status = fs::symlink_status(source, error);
            fs::path canonical_source;
            if (error || fs::is_symlink(source_status) || fs::is_other(source_status))
                detail = error ? error.message() :
                    "Workspace mutations reject symbolic links and special filesystem entries";
            else
                canonical_source = fs::weakly_canonical(source, error);
            if (detail.empty() && (error || !path_inside_roots(canonical_source, roots,
                    operation == file_operation_t::new_file ||
                    operation == file_operation_t::new_folder)))
                detail = error ? error.message() : "The resolved source escaped the workspace root";
            else if (detail.empty() && !destination.empty()) {
                error.clear();
                const fs::path canonical_parent = fs::weakly_canonical(destination.parent_path(), error);
                if (error || !path_inside_roots(canonical_parent, roots, true)) {
                    detail = error ? error.message() : "The resolved destination escaped the workspace root";
                } else {
                    destination = canonical_parent / destination.filename();
                    if (fs::exists(destination, error) || error)
                        detail = error ? error.message() : "The destination already exists";
                    else if (source_directory) {
                        const std::string source_key = path_key(path_to_utf8(canonical_source));
                        const std::string destination_key = path_key(path_to_utf8(destination));
                        if (destination_key.size() > source_key.size() &&
                            destination_key.compare(0, source_key.size(), source_key) == 0 &&
                            (destination_key[source_key.size()] == '/' ||
                             destination_key[source_key.size()] == '\\'))
                            detail = "A folder cannot be copied or moved inside itself";
                    }
                }
            }
            if (!detail.empty()) {
            }
            else if (operation == file_operation_t::new_file) {
                const HANDLE file = CreateFileW(destination.c_str(), GENERIC_WRITE,
                    0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
                succeeded = file != INVALID_HANDLE_VALUE;
                if (succeeded)
                    CloseHandle(file);
                detail = succeeded ? "File created" :
                    "The new file could not be created without replacing an existing item";
            } else if (operation == file_operation_t::new_folder) {
                succeeded = fs::create_directory(destination, error);
                detail = succeeded ? "Folder created" : (error ? error.message() : "The folder already exists");
            } else if (operation == file_operation_t::rename) {
                fs::rename(canonical_source, destination, error);
                succeeded = !error;
                detail = succeeded ? "Item renamed" : error.message();
            } else if (operation == file_operation_t::duplicate || operation == file_operation_t::copy) {
                std::uint64_t copied_bytes = 0;
                std::size_t copied_entries = 0;
                succeeded = bounded_copy_tree(canonical_source, destination, cancelled, detail,
                    copied_bytes, copied_entries);
                if (succeeded) detail = "Item copied";
            } else if (operation == file_operation_t::cut) {
                fs::rename(canonical_source, destination, error);
                succeeded = !error;
                detail = succeeded ? "Item moved" :
                    std::string("Move failed; cross-volume cut is not performed implicitly: ") + error.message();
            } else if (operation == file_operation_t::remove) {
                const auto removed = fs::remove_all(canonical_source, error);
                succeeded = !error && removed > 0;
                detail = succeeded ? "Item deleted" : (error ? error.message() : "The item no longer exists");
            } else if (operation == file_operation_t::open_with) {
                const auto launched = reinterpret_cast<std::intptr_t>(ShellExecuteW(nullptr,
                    L"openas", canonical_source.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
                succeeded = launched > 32;
                detail = succeeded ? "Open With launched" : "Windows could not open the Open With chooser";
            }
        } catch (const std::exception& exception) {
            detail = exception.what();
        } catch (...) {
            detail = "The filesystem operation failed with a non-standard exception";
        }
#endif
        aida::ui_thread::post_options_t options;
        options.subsystem = "project_explorer";
        options.label = "file_operation_result";
        options.phase = "worker_result";
        options.owner = "project_explorer.file_operation";
        options.priority = aida::ui_thread::priority_t::normal;
        const auto posted = aida::ui_thread::post([generation, succeeded,
                detail = std::move(detail)]() mutable {
            auto& current = file_operations();
            if (current.generation != generation)
                return;
            current.operation_pending = false;
            current.task_id = 0;
            current.dispatch_failed.reset();
            current.operation_error = succeeded ? std::string{} : detail;
            const bool clears_selection = succeeded &&
                (current.operation == file_operation_t::remove ||
                 current.operation == file_operation_t::rename ||
                 current.clipboard_cut);
            if (succeeded && current.clipboard_cut &&
                path_key(current.clipboard_path) == path_key(current.source)) {
                current.clipboard_path.clear();
                current.clipboard_cut = false;
                current.clipboard_directory = false;
            }
            if (clears_selection) {
                file_browser::selected_paths.clear();
                file_browser::selection_anchor_path.clear();
                file_browser::selected_idx = -1;
                ++file_browser::selection_revision;
            }
            file_browser::needs_refresh = true;
            if (!succeeded) {
                design::notification_t diagnostic;
                diagnostic.stable_id = "diagnostic.project_explorer.file_operation";
                diagnostic.owner = "project_explorer";
                diagnostic.target = current.source.c_str();
                diagnostic.summary = "Project Explorer filesystem operation failed";
                diagnostic.details = current.operation_error.c_str();
                diagnostic.semantic = design::semantic_t::error;
                diagnostic.attention_required = true;
                static_cast<void>(design::publish_notification(std::move(diagnostic)));
            }
        }, std::move(options));
        if (posted != aida::ui_thread::enqueue_result_t::accepted)
            dispatch_failed->store(true, std::memory_order_release);
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        state.operation_pending = false;
        state.operation_error = "The filesystem worker could not be scheduled: " + submitted.reject_reason;
        return {false, state.operation_error};
    }
    state.task_id = submitted.task_id;
    task_center::task_registration_t registration;
    registration.id = "project-explorer-file-operation-" + std::to_string(generation);
    registration.source = "Project Explorer";
    registration.owner = "project_explorer";
    registration.owner_view = "view.project_explorer";
    registration.owner_action = operation_label(operation);
    registration.target = state.source;
    registration.label = operation_label(operation);
    registration.stage = "Queued";
    registration.cancellation_is_safe = operation == file_operation_t::copy ||
        operation == file_operation_t::duplicate;
    if (registration.cancellation_is_safe)
        registration.callbacks.cancel = [task = submitted.task_id] {
            return aida::infra::executor::cancel(task);
        };
    if (!task_center::register_executor_job(submitted.task_id,
            std::move(registration))) {
        design::notification_t diagnostic;
        diagnostic.stable_id = "diagnostic.project_explorer.task_registration";
        diagnostic.owner = "project_explorer";
        diagnostic.target = state.source.c_str();
        diagnostic.summary = "Project Explorer work could not register in Background Tasks";
        diagnostic.details = "The bounded filesystem worker is running, but Task Center rejected its registration";
        diagnostic.semantic = design::semantic_t::error;
        diagnostic.attention_required = true;
        static_cast<void>(design::publish_notification(std::move(diagnostic)));
    }
    return {true, "The filesystem operation was queued"};
}

file_operation_result_t submit_batch_file_operation(file_operation_t operation,
    std::vector<file_operation_target_t> targets, const std::filesystem::path& destination_directory = {}) {
    auto& state = file_operations();
    if (state.operation_pending)
        return {false, "Another Project Explorer filesystem operation is already running"};
    if (targets.empty()) return {false, "Select at least one Project Explorer item"};
    if (targets.size() > 100000)
        return {false, "Project Explorer batch operations are limited to 100,000 selected items"};
    const std::vector<std::string> roots = file_browser::roots;
    for (const auto& target : targets) {
        if (!path_inside_root(path_from_utf8(target.path), false))
            return {false, "Every selected item must remain inside an open Project Explorer root"};
    }
    if (!destination_directory.empty() && !path_inside_root(destination_directory, true))
        return {false, "The paste destination is outside the open Project Explorer roots"};
    state.operation_pending = true;
    state.operation_error.clear();
    state.sources = targets;
    const std::uint64_t generation = ++state.generation;
    auto cancelled = std::make_shared<std::atomic<bool>>(false);
    auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
    state.dispatch_failed = dispatch_failed;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "project_explorer";
    submission.label = "project_explorer.batch_file_operation";
    submission.thread_class = "bounded_filesystem_io";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 3;
    submission.generation = generation;
    submission.cancel_hook = [cancelled] { cancelled->store(true, std::memory_order_release); };
    submission.body = [operation, targets = std::move(targets), destination_directory,
            roots, cancelled, dispatch_failed, generation]() mutable {
        bool succeeded = false;
        bool partial = false;
        std::string detail;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		static_cast<void>(operation);
        succeeded = !cancelled->load(std::memory_order_acquire);
        detail = succeeded ? "Preview batch filesystem operation completed deterministically" :
            "The preview batch filesystem operation was cancelled";
#else
        namespace fs = std::filesystem;
        std::vector<std::pair<fs::path, fs::path>> completed;
        std::size_t permanently_completed = 0;
        std::uint64_t total_bytes = 0;
        std::size_t entry_count = 0;
        const auto recover_completed = [&]() {
            bool proven = true;
            for (auto iterator = completed.rbegin(); iterator != completed.rend(); ++iterator) {
                std::error_code recovery_error;
                if (operation == file_operation_t::copy)
                    fs::remove_all(iterator->second, recovery_error);
                else if (operation == file_operation_t::cut)
                    fs::rename(iterator->second, iterator->first, recovery_error);
                if (recovery_error) proven = false;
            }
            return proven;
        };
        try {
            completed.reserve(targets.size());
            for (const auto& target : targets) {
                if (cancelled->load(std::memory_order_acquire)) {
                    detail = "The batch filesystem operation was cancelled";
                    break;
                }
                std::error_code error;
                const fs::path requested = path_from_utf8(target.path);
                const fs::file_status status = fs::symlink_status(requested, error);
                if (error || fs::is_symlink(status) || fs::is_other(status)) {
                    detail = error ? error.message() :
                        "Workspace mutations reject symbolic links and special filesystem entries";
                    break;
                }
                const fs::path source = fs::weakly_canonical(requested, error);
                if (error || !path_inside_roots(source, roots, false)) {
                    detail = error ? error.message() : "A selected item escaped its retained workspace root";
                    break;
                }
                if (operation == file_operation_t::remove) {
                    const auto removed = fs::remove_all(source, error);
                    if (error || removed == 0) {
                        detail = error ? error.message() : "A selected item no longer exists";
                        partial = !completed.empty();
                        break;
                    }
                    ++permanently_completed;
                    continue;
                }
                const fs::path parent = fs::weakly_canonical(destination_directory, error);
                if (error || !path_inside_roots(parent, roots, true)) {
                    detail = error ? error.message() : "The resolved paste destination escaped its workspace root";
                    break;
                }
                const fs::path destination = parent / source.filename();
                if (fs::exists(destination, error) || error) {
                    detail = error ? error.message() : "A paste destination already exists: " + destination.u8string();
                    break;
                }
                if (target.directory) {
                    const std::string source_key = path_key(source.u8string());
                    const std::string destination_key = path_key(destination.u8string());
                    if (destination_key.size() > source_key.size() &&
                        destination_key.compare(0, source_key.size(), source_key) == 0 &&
                        (destination_key[source_key.size()] == '/' || destination_key[source_key.size()] == '\\')) {
                        detail = "A folder cannot be copied or moved inside itself";
                        break;
                    }
                }
                if (operation == file_operation_t::copy) {
                    if (!bounded_copy_tree(source, destination, cancelled, detail,
                            total_bytes, entry_count))
                        break;
                } else {
                    fs::rename(source, destination, error);
                    if (error) {
                        detail = "Move failed; cross-volume cut is not performed implicitly: " + error.message();
                        break;
                    }
                }
                completed.emplace_back(source, destination);
            }
            succeeded = operation == file_operation_t::remove
                ? permanently_completed == targets.size()
                : completed.size() == targets.size();
            if (!succeeded && (operation == file_operation_t::copy ||
                    operation == file_operation_t::cut)) {
                if (!recover_completed()) {
                    partial = true;
                    detail += operation == file_operation_t::cut
                        ? "; one or more completed moves could not be rolled back"
                        : "; one or more copied destinations could not be cleaned up";
                }
            }
            if (succeeded)
                detail = operation == file_operation_t::remove
                    ? "Selected items deleted" : operation == file_operation_t::cut
                        ? "Selected items moved" : "Selected items copied";
            else if (operation == file_operation_t::remove && permanently_completed != 0)
                partial = true;
        } catch (const std::exception& exception) {
            detail = exception.what();
            if (!completed.empty() || permanently_completed != 0) {
                if (operation == file_operation_t::remove)
                    partial = permanently_completed != 0;
                else if (!recover_completed()) {
                    partial = true;
                    detail += operation == file_operation_t::cut
                        ? "; one or more completed moves could not be rolled back"
                        : "; one or more copied destinations could not be cleaned up";
                }
            }
        } catch (...) {
            detail = "The batch filesystem operation failed with a non-standard exception";
            if (!completed.empty() || permanently_completed != 0) {
                if (operation == file_operation_t::remove)
                    partial = permanently_completed != 0;
                else if (!recover_completed()) {
                    partial = true;
                    detail += operation == file_operation_t::cut
                        ? "; one or more completed moves could not be rolled back"
                        : "; one or more copied destinations could not be cleaned up";
                }
            }
        }
#endif
        aida::ui_thread::post_options_t options;
        options.subsystem = "project_explorer";
        options.label = "batch_file_operation_result";
        options.phase = "worker_result";
        options.owner = "project_explorer.file_operation";
        const auto posted = aida::ui_thread::post([generation, succeeded, partial,
                detail = std::move(detail)]() mutable {
            auto& current = file_operations();
            if (current.generation != generation) return;
            current.operation_pending = false;
            current.task_id = 0;
            current.dispatch_failed.reset();
            current.operation_error = succeeded ? std::string{} : detail;
            const bool clears_selection = succeeded &&
                (current.operation == file_operation_t::remove || current.clipboard_cut);
            if (succeeded && current.clipboard_cut) {
                current.clipboard_targets.clear();
                current.clipboard_path.clear();
                current.clipboard_cut = false;
            }
            if (clears_selection) {
                file_browser::selected_paths.clear();
                file_browser::selection_anchor_path.clear();
                file_browser::selected_idx = -1;
                ++file_browser::selection_revision;
            }
            file_browser::needs_refresh = true;
            if (!succeeded) {
                design::notification_t diagnostic;
                diagnostic.stable_id = partial
                    ? "diagnostic.project_explorer.batch_partial"
                    : "diagnostic.project_explorer.batch_failure";
                diagnostic.owner = "project_explorer";
                diagnostic.target = current.source.c_str();
                diagnostic.summary = partial
                    ? "Project Explorer batch operation completed only partially"
                    : "Project Explorer batch operation failed";
                diagnostic.details = current.operation_error.c_str();
                diagnostic.semantic = design::semantic_t::error;
                diagnostic.attention_required = true;
                static_cast<void>(design::publish_notification(std::move(diagnostic)));
            }
        }, std::move(options));
        if (posted != aida::ui_thread::enqueue_result_t::accepted)
            dispatch_failed->store(true, std::memory_order_release);
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        state.operation_pending = false;
        state.operation_error = "The batch filesystem worker could not be scheduled: " + submitted.reject_reason;
        return {false, state.operation_error};
    }
    state.task_id = submitted.task_id;
    task_center::task_registration_t registration;
    registration.id = "project-explorer-batch-operation-" + std::to_string(generation);
    registration.source = "Project Explorer";
    registration.owner = "project_explorer";
    registration.owner_view = "view.project_explorer";
    registration.owner_action = operation_label(operation);
    registration.target = std::to_string(state.sources.size()) + " selected items";
    registration.label = operation_label(operation);
    registration.stage = "Queued";
    registration.cancellation_is_safe = operation == file_operation_t::copy;
    if (registration.cancellation_is_safe)
        registration.callbacks.cancel = [task = submitted.task_id] {
            return aida::infra::executor::cancel(task);
        };
    if (!task_center::register_executor_job(submitted.task_id, std::move(registration))) {
        design::notification_t diagnostic;
        diagnostic.stable_id = "diagnostic.project_explorer.batch_task_registration";
        diagnostic.owner = "project_explorer";
        diagnostic.target = state.source.c_str();
        diagnostic.summary = "Project Explorer batch work could not register in Background Tasks";
        diagnostic.details = "The bounded filesystem worker is running, but Task Center rejected its registration";
        diagnostic.semantic = design::semantic_t::error;
        diagnostic.attention_required = true;
        static_cast<void>(design::publish_notification(std::move(diagnostic)));
    }
    return {true, "The batch filesystem operation was queued"};
}

bool context_key_pressed(context_menu_open_origin_t& origin) {
    if (ImGui::IsKeyPressed(ImGuiKey_Menu, false)) {
        origin = context_menu_open_origin_t::menu_key;
        return true;
    }
    if (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false)) {
        origin = context_menu_open_origin_t::shift_f10;
        return true;
    }
    return false;
}

std::string path_key(const std::string& path) {
    try {
        std::string normalized = path_to_utf8(path_from_utf8(path).lexically_normal());
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        return normalized;
    } catch (...) {
        return {};
    }
}

std::string path_leaf(const std::string& path) {
    try {
        const std::string value = path_to_utf8(path_from_utf8(path).filename());
        return value.empty() ? path : value;
    } catch (...) {
        return path;
    }
}

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

bool explorer_entry_matches(const FileBrowserEntry& entry, const std::string& normalized_filter) {
    if (normalized_filter.empty())
        return true;
    return lowercase(entry.name).find(normalized_filter) != std::string::npos ||
        lowercase(entry.full_path).find(normalized_filter) != std::string::npos;
}

void rebuild_explorer_filter(explorer_presentation_state_t& state) {
    state.visible_indices.clear();
    const std::string normalized_filter = lowercase(state.filter);
    if (!normalized_filter.empty()) {
        state.visible_indices.reserve(file_browser::entries.size());
        for (std::size_t index = 0; index < file_browser::entries.size(); ++index) {
            if (explorer_entry_matches(file_browser::entries[index], normalized_filter))
                state.visible_indices.push_back(static_cast<int>(index));
        }
    }
    state.applied_filter = state.filter;
    state.indexed_root = file_browser::current_dir;
    state.indexed_entry_count = file_browser::entries.size();
    state.filter_dirty = false;
}

bool explorer_path_selected(const std::string& path) {
    return file_browser::selected_paths.find(path_key(path)) !=
        file_browser::selected_paths.end();
}

void replace_explorer_selection(int index) {
    if (index < 0 || static_cast<std::size_t>(index) >= file_browser::entries.size()) return;
    const std::string key = path_key(file_browser::entries[static_cast<std::size_t>(index)].full_path);
    file_browser::selected_paths.clear();
    if (!key.empty()) file_browser::selected_paths.insert(key);
    file_browser::selection_anchor_path = key;
    file_browser::selected_idx = index;
    file_browser::selection_error.clear();
    file_browser::selection_interaction_generation = file_browser::index_generation;
    ++file_browser::selection_revision;
}

void toggle_explorer_selection(int index) {
    if (index < 0 || static_cast<std::size_t>(index) >= file_browser::entries.size()) return;
    const std::string key = path_key(file_browser::entries[static_cast<std::size_t>(index)].full_path);
    if (key.empty()) return;
    if (file_browser::index_state == file_browser::index_state_t::loading &&
        file_browser::selection_interaction_generation != file_browser::index_generation) {
        file_browser::selected_paths.clear();
        file_browser::selection_anchor_path.clear();
    }
    if (file_browser::selected_paths.find(key) != file_browser::selected_paths.end())
        file_browser::selected_paths.erase(key);
    else if (file_browser::selected_paths.size() < 100000)
        file_browser::selected_paths.insert(key);
    else
        file_browser::selection_error = "Project Explorer selection is limited to 100,000 items";
    file_browser::selection_anchor_path = key;
    file_browser::selection_interaction_generation = file_browser::index_generation;
    file_browser::selected_idx = explorer_path_selected(
        file_browser::entries[static_cast<std::size_t>(index)].full_path) ? index : -1;
    ++file_browser::selection_revision;
}

void extend_explorer_selection(int index) {
    if (index < 0 || static_cast<std::size_t>(index) >= file_browser::entries.size()) return;
    const auto& presentation = explorer_presentation();
    std::vector<int> order;
    if (presentation.applied_filter.empty()) {
        order.resize(file_browser::entries.size());
        for (std::size_t position = 0; position < order.size(); ++position)
            order[position] = static_cast<int>(position);
    } else {
        order = presentation.visible_indices;
    }
    auto current = std::find(order.begin(), order.end(), index);
    auto anchor = std::find_if(order.begin(), order.end(), [](int candidate) {
        return candidate >= 0 && static_cast<std::size_t>(candidate) < file_browser::entries.size() &&
            path_key(file_browser::entries[static_cast<std::size_t>(candidate)].full_path) ==
                file_browser::selection_anchor_path;
    });
    if (current == order.end() || anchor == order.end()) {
        replace_explorer_selection(index);
        return;
    }
    const auto first = (std::min)(current, anchor);
    const auto last = (std::max)(current, anchor);
    const std::size_t requested = static_cast<std::size_t>(std::distance(first, last)) + 1;
    if (requested > 100000) {
        file_browser::selection_error = "Project Explorer range selection is limited to 100,000 items";
        return;
    }
    file_browser::selected_paths.clear();
    for (auto iterator = first; iterator != std::next(last); ++iterator) {
        const std::string key = path_key(
            file_browser::entries[static_cast<std::size_t>(*iterator)].full_path);
        if (!key.empty()) file_browser::selected_paths.insert(key);
    }
    file_browser::selected_idx = index;
    file_browser::selection_error.clear();
    file_browser::selection_interaction_generation = file_browser::index_generation;
    ++file_browser::selection_revision;
}

void draw_folder_icon(ImDrawList* draw, ImVec2 center, float scale, ImU32 color, bool expanded) {
    const float stroke = (std::max)(1.0f, 1.25f * scale);
    const ImVec2 minimum(center.x - 6.5f * scale, center.y - 4.0f * scale);
    const ImVec2 maximum(center.x + 6.5f * scale, center.y + 5.0f * scale);
    draw->AddRect(minimum, maximum, color, 1.5f * scale, 0, stroke);
    draw->AddLine(ImVec2(minimum.x + 0.5f * scale, minimum.y),
        ImVec2(minimum.x + 3.0f * scale, minimum.y - 3.0f * scale), color, stroke);
    draw->AddLine(ImVec2(minimum.x + 3.0f * scale, minimum.y - 3.0f * scale),
        ImVec2(center.x + 1.0f * scale, minimum.y - 3.0f * scale), color, stroke);
    draw->AddLine(ImVec2(center.x + 1.0f * scale, minimum.y - 3.0f * scale),
        ImVec2(center.x + 3.0f * scale, minimum.y), color, stroke);
    if (expanded)
        draw->AddLine(ImVec2(minimum.x + 2.0f * scale, center.y + 1.0f * scale),
            ImVec2(maximum.x - 2.0f * scale, center.y + 1.0f * scale), color, stroke);
}

void draw_file_icon(ImDrawList* draw, ImVec2 center, float scale, ImU32 color) {
    const float stroke = (std::max)(1.0f, 1.25f * scale);
    const ImVec2 minimum(center.x - 5.0f * scale, center.y - 7.0f * scale);
    const ImVec2 maximum(center.x + 5.0f * scale, center.y + 7.0f * scale);
    draw->AddRect(minimum, maximum, color, 1.0f * scale, 0, stroke);
    draw->AddLine(ImVec2(center.x + 1.0f * scale, minimum.y),
        ImVec2(maximum.x, minimum.y + 4.0f * scale), color, stroke);
    draw->AddLine(ImVec2(center.x + 1.0f * scale, minimum.y),
        ImVec2(center.x + 1.0f * scale, minimum.y + 4.0f * scale), color, stroke);
    draw->AddLine(ImVec2(center.x + 1.0f * scale, minimum.y + 4.0f * scale),
        ImVec2(maximum.x, minimum.y + 4.0f * scale), color, stroke);
}

void draw_disclosure(ImDrawList* draw, ImVec2 center, float scale, ImU32 color, bool expanded) {
    const float half = 3.0f * scale;
    if (expanded) {
        draw->AddTriangleFilled(ImVec2(center.x - half, center.y - half * 0.6f),
            ImVec2(center.x + half, center.y - half * 0.6f),
            ImVec2(center.x, center.y + half), color);
    } else {
        draw->AddTriangleFilled(ImVec2(center.x - half * 0.6f, center.y - half),
            ImVec2(center.x - half * 0.6f, center.y + half),
            ImVec2(center.x + half, center.y), color);
    }
}

struct explorer_document_state_t {
    bool modified = false;
    bool conflict = false;
};

explorer_document_state_t document_state_for(const std::string& path) {
    explorer_document_state_t state;
    const std::string key = path_key(path);
    for (const auto& tab : file_tabs::tabs) {
        if (path_key(tab.filepath) != key)
            continue;
        state.modified = tab.dirty;
        state.conflict = tab.external_conflict;
        break;
    }
    return state;
}

bool render_explorer_row(int index, float row_height, float scale, int& focused_index,
    bool& row_context_opened) {
    const FileBrowserEntry entry = file_browser::entries[static_cast<std::size_t>(index)];
    const auto& theme = aida::ui::resolved();
    ImGui::PushID(entry.full_path.c_str());
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const float width = (std::max)(1.0f, ImGui::GetContentRegionAvail().x);
    const bool selected = explorer_path_selected(entry.full_path);
    const bool activated = ImGui::Selectable("##explorer_row", selected,
        ImGuiSelectableFlags_AllowDoubleClick,
        ImVec2(width, row_height));
    const bool focused = ImGui::IsItemFocused();
    const bool hovered = ImGui::IsItemHovered();
    const bool left_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
    const bool double_clicked = left_clicked && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
    const bool context_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
    const float indent = static_cast<float>((std::max)(0, entry.depth)) * 14.0f * scale;
    const float disclosure_x = origin.x + 8.0f * scale + indent;
    const float icon_x = disclosure_x + 14.0f * scale;
    const float center_y = origin.y + row_height * 0.5f;
    const bool disclosure_clicked = left_clicked && entry.is_dir &&
        ImGui::GetIO().MousePos.x <= disclosure_x + 7.0f * scale;
    if (focused)
        focused_index = index;
    if ((activated || left_clicked) && !ui_input_gate::popup_blocks_background_input()) {
        if (ImGui::GetIO().KeyShift)
            extend_explorer_selection(index);
        else if (ImGui::GetIO().KeyCtrl)
            toggle_explorer_selection(index);
        else
            replace_explorer_selection(index);
        const bool keyboard_activated = activated && !left_clicked;
        if (entry.is_dir && (disclosure_clicked || double_clicked || keyboard_activated)) {
            file_browser::toggle_dir(index);
            explorer_presentation().filter_dirty = true;
        } else if (!entry.is_dir && (double_clicked || keyboard_activated)) {
            file_browser::open_file(index);
        }
    }
    if (context_clicked && !ui_input_gate::popup_blocks_background_input()) {
        if (!explorer_path_selected(entry.full_path))
            replace_explorer_selection(index);
        row_context_opened = true;
        application_ui::open_explorer_context_menu(index, context_menu_open_origin_t::pointer);
    }
    ImDrawList* draw = ImGui::GetWindowDrawList();
    if (entry.is_dir)
        draw_disclosure(draw, ImVec2(disclosure_x, center_y), scale,
            hovered ? theme.text_primary : theme.text_dim, entry.expanded);
    const ImU32 icon_color = selected ? theme.accent_u32 :
        (entry.is_dir ? theme.text_secondary : theme.text_dim);
    if (entry.is_dir)
        draw_folder_icon(draw, ImVec2(icon_x, center_y), scale, icon_color, entry.expanded);
    else
        draw_file_icon(draw, ImVec2(icon_x, center_y), scale, icon_color);
    const explorer_document_state_t document = entry.is_dir ? explorer_document_state_t{} :
        document_state_for(entry.full_path);
    const float indicator_width = document.modified || document.conflict ? 14.0f * scale : 0.0f;
    const ImVec2 text_min(icon_x + 11.0f * scale,
        origin.y + (row_height - ImGui::GetFontSize()) * 0.5f);
    const ImVec2 text_max(origin.x + width - 6.0f * scale - indicator_width, origin.y + row_height);
    draw->PushClipRect(origin, ImVec2(origin.x + width, origin.y + row_height), true);
    ImGui::RenderTextEllipsis(draw, text_min, text_max, text_max.x,
        entry.name.c_str(), nullptr, nullptr);
    if (document.modified || document.conflict) {
        const ImU32 state_color = document.conflict ? design::semantic_color(design::semantic_t::error) :
            design::semantic_color(design::semantic_t::changed);
        draw->AddCircleFilled(ImVec2(origin.x + width - 8.0f * scale, center_y), 2.5f * scale, state_color);
    }
    draw->PopClipRect();
    if (focused)
        design::draw_focus_ring_for_last_item();
    if (hovered) {
        ImGui::BeginTooltip();
        ImGui::TextUnformatted(entry.full_path.c_str());
        if (document.conflict)
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(design::semantic_color(design::semantic_t::error)),
                "Changed on disk while this file has editor state");
        else if (document.modified)
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(design::semantic_color(design::semantic_t::changed)),
                "Modified in the code editor");
        ImGui::EndTooltip();
    }
    ImGui::PopID();
    return activated;
}

void open_search_result(const workspace_search::match_result_t& result) {
    file_tabs::request_document_open(result.filepath, path_leaf(result.filepath),
        (std::max)(0, result.line_number - 1), (std::max)(0, result.col_start));
    application_views::open_or_focus(stable_view_id_t("document.code"));
}

void start_workspace_search() {
    if (!file_browser::roots.empty())
        workspace_search::start_search(file_browser::roots);
    else
        workspace_search::start_search(file_browser::current_dir);
}

void request_recent_open(const std::string& path) {
    file_browser::pending_open_path = path;
    file_browser::pending_open_filename = path_leaf(path);
    file_browser::pending_open_should_open = true;
    file_browser::pending_open_modal_visible = true;
}

const std::vector<std::string>& recent_workspace_paths() {
	static std::string source;
	static std::vector<std::string> paths;
	if (source == g_sa_settings.recent_workspaces_json)
		return paths;
	source = g_sa_settings.recent_workspaces_json;
	paths.clear();
	if (source.empty())
		return paths;
	const auto json = nlohmann::json::parse(source, nullptr, false);
    if (json.is_discarded() || !json.is_array())
        return paths;
    std::unordered_set<std::string> seen;
    for (const auto& value : json) {
        if (!value.is_string())
            continue;
        std::string path = value.get<std::string>();
        if (path.empty() || !seen.insert(path_key(path)).second)
            continue;
        paths.push_back(std::move(path));
        if (paths.size() == 32)
            break;
    }
    return paths;
}

bool session_is_open(const std::string& path) {
    const std::string expected = path_key(path);
    for (std::size_t index = 0; index < analysis_session::session_count(); ++index) {
        const auto session = analysis_session::session_handle_at(index);
        if (session && path_key(session->path) == expected)
            return true;
    }
    return false;
}

const std::string* previous_closed_session(const std::vector<std::string>& paths) {
    const auto found = std::find_if(paths.begin(), paths.end(), [](const std::string& path) {
        return !session_is_open(path);
    });
    return found == paths.end() ? nullptr : &*found;
}

bool render_start_action(const char* stable_id, const char* label, const char* description,
    float width, action_invocation_source_t source = action_invocation_source_t::toolbar) {
    const auto presentation = application_ui::present_action(stable_id);
    const bool available = presentation.visible && presentation.enabled;
    ImGui::PushID(stable_id);
    ImGui::BeginDisabled(!available);
    const bool invoked = ImGui::Button(label, ImVec2(width, design::metrics().control_height +
        aida::ui::scale_px(8.0f, design::metrics().scale)));
    ImGui::EndDisabled();
    design::draw_focus_ring_for_last_item();
    const char* detail = !available && !presentation.disabled_reason.empty()
        ? presentation.disabled_reason.c_str()
        : !presentation.description.empty() ? presentation.description.c_str() : description;
    design::tooltip_for_last_item(detail,
        presentation.shortcut.empty() ? nullptr : presentation.shortcut.c_str());
    ImGui::PopID();
    if (invoked) {
        static_cast<void>(application_ui::execute_action(stable_id, source));
        if (std::strcmp(stable_id, "tools.load_binary") == 0 ||
            std::strcmp(stable_id, "file.open_folder") == 0 ||
            std::strcmp(stable_id, "tools.attach_process") == 0 ||
            std::strcmp(stable_id, "debugger.launch") == 0 ||
            std::strcmp(stable_id, "file.restore_previous_session") == 0 ||
            std::strcmp(stable_id, "file.new") == 0 ||
            std::strcmp(stable_id, "file.open") == 0)
            application_views::dismiss_start_center_when_work_available();
    }
    return invoked;
}

void render_start_section_label(const char* label, const char* detail = nullptr) {
    design::text(design::text_role_t::title, label);
    if (detail) {
        ImGui::SameLine();
        design::text(design::text_role_t::caption, detail);
    }
    ImGui::Spacing();
}

}

file_operation_capability_t file_operation_capability(file_operation_t operation,
    const std::string& path, bool directory) {
    try {
    const auto& state = file_operations();
    if (state.operation_pending)
        return {false, "Another Project Explorer filesystem operation is already running"};
    if (file_browser::roots.empty())
        return {false, "Open a Project Explorer root first"};
    if ((!path.empty() && path_key(path).empty()) ||
        std::any_of(file_browser::roots.begin(), file_browser::roots.end(),
            [](const std::string& root) { return path_key(root).empty(); }))
        return {false, "The selected path or workspace root is not valid UTF-8 and cannot be converted safely"};
    if (operation == file_operation_t::paste) {
        if (state.clipboard_targets.empty())
            return {false, "Cut or copy a Project Explorer item first"};
        if (state.clipboard_cut) {
            for (const auto& staged_target : state.clipboard_targets) {
                const std::string staged = path_key(staged_target.path);
                if (staged.empty())
                    return {false, "A staged clipboard path is not valid UTF-8 and cannot be converted safely"};
                for (const auto& tab : file_tabs::tabs) {
                    const std::string document = path_key(tab.filepath);
                    if (document == staged || (staged_target.directory &&
                        document.size() > staged.size() &&
                        document.compare(0, staged.size(), staged) == 0 &&
                        (document[staged.size()] == '/' || document[staged.size()] == '\\')))
                        return {false, "Close editor documents under every cut path before moving the selection"};
                }
            }
        }
        const std::filesystem::path target = directory
            ? path_from_utf8(path) : path_from_utf8(path).parent_path();
        return path_inside_root(target, true)
            ? file_operation_capability_t{true, {}}
            : file_operation_capability_t{false, "Select a destination inside an open Project Explorer root"};
    }
    if (path.empty())
        return {false, "Select a file or folder first"};
    const bool allow_root = operation == file_operation_t::new_file ||
        operation == file_operation_t::new_folder || operation == file_operation_t::terminal_here;
    if (!path_inside_root(path_from_utf8(path), allow_root))
        return {false, allow_root ? "The selected destination is outside the open Project Explorer roots" :
            "Workspace roots cannot be renamed, moved, copied, duplicated, or deleted"};
    if (operation == file_operation_t::open_with && directory)
        return {false, "Open With is available for files; use Terminal Here for folders"};
    if (operation == file_operation_t::rename || operation == file_operation_t::cut ||
        operation == file_operation_t::remove) {
        const std::string selected = path_key(path);
        for (const auto& tab : file_tabs::tabs) {
            const std::string document = path_key(tab.filepath);
            const bool affected = document == selected || (directory &&
                document.size() > selected.size() &&
                document.compare(0, selected.size(), selected) == 0 &&
                (document[selected.size()] == '/' || document[selected.size()] == '\\'));
            if (!affected)
                continue;
            if (tab.dirty)
                return {false, "Save or close the modified editor document before changing its path"};
            if (tab.save_in_progress || tab.load_in_progress)
                return {false, "Wait for the editor document operation to finish before changing its path"};
            return {false, "Close editor documents under this path before renaming, moving, or deleting it"};
        }
    }
    return {true, {}};
    } catch (const std::exception&) {
        return {false, "The selected path is not valid UTF-8 or cannot be represented by the native filesystem"};
    } catch (...) {
        return {false, "The selected path could not be converted to a native filesystem path"};
    }
}

file_operation_result_t request_file_operation(file_operation_t operation,
    const std::string& path, bool directory) {
    try {
    const auto capability = file_operation_capability(operation, path, directory);
    if (!capability.enabled)
        return {false, capability.reason};
    auto& state = file_operations();
    state.operation = operation;
    state.source = path_to_utf8(path_from_utf8(path).lexically_normal());
    state.source_directory = directory;
    state.sources = {{state.source, directory}};
    state.validation_error.clear();
    state.operation_error.clear();
    if (operation == file_operation_t::cut || operation == file_operation_t::copy) {
        state.clipboard_path = state.source;
        state.clipboard_targets = {{state.source, directory}};
        state.clipboard_cut = operation == file_operation_t::cut;
        state.clipboard_directory = directory;
        return {true, operation == file_operation_t::cut
            ? "The item is ready to move; choose Paste in a destination folder"
            : "The item is ready to copy; choose Paste in a destination folder"};
    }
    if (operation == file_operation_t::paste) {
        const std::filesystem::path destination_directory = directory
            ? path_from_utf8(path) : path_from_utf8(path).parent_path();
        if (state.clipboard_targets.size() > 1)
            return submit_batch_file_operation(state.clipboard_cut
                ? file_operation_t::cut : file_operation_t::copy,
                state.clipboard_targets, destination_directory);
        const std::filesystem::path source = path_from_utf8(state.clipboard_targets.front().path);
        state.source = path_to_utf8(source);
        state.source_directory = state.clipboard_targets.front().directory;
        return submit_file_operation(state.clipboard_cut
            ? file_operation_t::cut : file_operation_t::copy,
            source, destination_directory / source.filename(), state.source_directory);
    }
    if (operation == file_operation_t::open_with ||
        operation == file_operation_t::terminal_here) {
        if (operation == file_operation_t::terminal_here) {
            const std::filesystem::path selected = path_from_utf8(state.source);
            const std::string directory_path = path_to_utf8(directory
                ? selected : selected.parent_path());
            const auto terminal = output_views::terminal_new_at(directory_path);
            if (!terminal.succeeded)
                return {false, terminal.detail};
            const auto opened = application_views::open_or_focus(
                stable_view_id_t("view.terminal"));
            return opened.ok() ? file_operation_result_t{true, "Integrated terminal opened"}
                : file_operation_result_t{false, opened.detail};
        }
        return submit_file_operation(operation, path_from_utf8(state.source), {}, directory);
    }
    if (operation == file_operation_t::remove) {
        state.delete_dialog_open = true;
        state.delete_dialog_requested = true;
        return {true, "Review the exact deletion target before continuing"};
    }
    std::string proposed;
    if (operation == file_operation_t::rename)
        proposed = path_to_utf8(path_from_utf8(path).filename());
    else if (operation == file_operation_t::duplicate) {
        const auto source = path_from_utf8(path);
        proposed = path_to_utf8(source.stem()) + " copy" + path_to_utf8(source.extension());
    }
    std::snprintf(state.name, sizeof(state.name), "%s", proposed.c_str());
    state.name_dialog_open = true;
    state.name_dialog_requested = true;
    return {true, "Enter and validate the destination name"};
    } catch (const std::exception&) {
        return {false, "The selected path is not valid UTF-8 or cannot be represented by the native filesystem"};
    } catch (...) {
        return {false, "The selected path could not be converted to a native filesystem path"};
    }
}

file_operation_capability_t file_operation_capability(file_operation_t operation,
    const std::vector<file_operation_target_t>& targets) {
    if (targets.empty()) return {false, "Select a file or folder first"};
    if (targets.size() == 1)
        return file_operation_capability(operation, targets.front().path,
            targets.front().directory);
    if (targets.size() > 100000)
        return {false, "Project Explorer batch operations are limited to 100,000 selected items"};
    if (operation != file_operation_t::copy && operation != file_operation_t::cut &&
        operation != file_operation_t::remove)
        return {false, "This action requires exactly one selected Project Explorer item"};
    std::vector<std::string> keys;
    keys.reserve(targets.size());
    for (const auto& target : targets) {
        const auto capability = file_operation_capability(operation,
            target.path, target.directory);
        if (!capability.enabled) return capability;
        keys.push_back(path_key(target.path));
    }
    const std::unordered_set<std::string> selected_keys(keys.begin(), keys.end());
    for (const auto& key : keys) {
        std::size_t boundary = key.size();
        while (boundary > 0) {
            boundary = key.find_last_of("/\\", boundary - 1);
            if (boundary == std::string::npos) break;
            const std::string ancestor = key.substr(0, boundary);
            if (!ancestor.empty() && selected_keys.find(ancestor) != selected_keys.end())
                return {false, "The selection contains both a folder and one of its descendants; deselect the descendant"};
            if (boundary == 0) break;
        }
    }
    return {true, {}};
}

file_operation_result_t request_file_operation(file_operation_t operation,
    const std::vector<file_operation_target_t>& targets) {
    const auto capability = file_operation_capability(operation, targets);
    if (!capability.enabled) return {false, capability.reason};
    if (targets.size() == 1)
        return request_file_operation(operation, targets.front().path,
            targets.front().directory);
    auto& state = file_operations();
    state.operation = operation;
    state.sources = targets;
    state.source = std::to_string(targets.size()) + " selected items";
    state.validation_error.clear();
    state.operation_error.clear();
    if (operation == file_operation_t::copy || operation == file_operation_t::cut) {
        state.clipboard_targets = targets;
        state.clipboard_path = targets.front().path;
        state.clipboard_directory = targets.front().directory;
        state.clipboard_cut = operation == file_operation_t::cut;
        return {true, operation == file_operation_t::cut
            ? "The selected items are ready to move; choose Paste in a destination folder"
            : "The selected items are ready to copy; choose Paste in a destination folder"};
    }
    state.delete_dialog_open = true;
    state.delete_dialog_requested = true;
    return {true, "Review the exact selected deletion set before continuing"};
}

void render_global_file_operation_dialogs() {
    auto& state = file_operations();
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport ? viewport->WorkPos : ImVec2(0.0f, 0.0f),
        ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(1.0f, 1.0f), ImGuiCond_Always);
    ImGui::Begin("##project_explorer_dialog_host", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoInputs |
        ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoDocking);
    if (state.dispatch_failed &&
        state.dispatch_failed->exchange(false, std::memory_order_acq_rel)) {
        state.operation_pending = false;
        state.task_id = 0;
        state.dispatch_failed.reset();
        state.operation_error = "The filesystem worker completed, but its result could not return to the UI owner";
        design::notification_t diagnostic;
        diagnostic.stable_id = "diagnostic.project_explorer.dispatch";
        diagnostic.owner = "project_explorer";
        diagnostic.target = state.source.c_str();
        diagnostic.summary = "Project Explorer result publication failed";
        diagnostic.details = state.operation_error.c_str();
        diagnostic.semantic = design::semantic_t::error;
        diagnostic.attention_required = true;
        static_cast<void>(design::publish_notification(std::move(diagnostic)));
    }
    if (state.name_dialog_requested) {
        design::open_dialog("##project_explorer_name", operation_label(state.operation));
        state.name_dialog_requested = false;
    }
    if (state.delete_dialog_requested) {
        design::open_dialog("##project_explorer_delete", "Delete Workspace Item");
        state.delete_dialog_requested = false;
    }
    if (state.name_dialog_open && design::begin_dialog("##project_explorer_name",
            operation_label(state.operation), ImVec2(520.0f, 230.0f), ImVec2(380.0f, 200.0f))) {
        ImGui::TextWrapped("Target directory: %s",
            (state.source_directory && (state.operation == file_operation_t::new_file ||
                state.operation == file_operation_t::new_folder)
                ? state.source : path_to_utf8(path_from_utf8(state.source).parent_path())).c_str());
        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::InputText("Name", state.name, sizeof(state.name)))
            valid_leaf_name(state.name, state.validation_error);
        if (!state.validation_error.empty())
            design::text(design::text_role_t::caption, state.validation_error.c_str());
        std::string validation;
        const bool valid = valid_leaf_name(state.name, validation);
        const auto footer = design::dialog_footer("project-explorer-name-footer",
            state.operation == file_operation_t::rename ? "Rename" :
            state.operation == file_operation_t::duplicate ? "Duplicate" : "Create",
            valid, false);
        if (footer.confirmed) {
            const std::filesystem::path source = path_from_utf8(state.source);
            const std::filesystem::path base = state.source_directory &&
                (state.operation == file_operation_t::new_file ||
                 state.operation == file_operation_t::new_folder)
                ? source : source.parent_path();
            const auto queued = submit_file_operation(state.operation, source,
                base / state.name, state.source_directory);
            if (queued.accepted) {
                state.name_dialog_open = false;
                ImGui::CloseCurrentPopup();
            } else {
                state.validation_error = queued.detail;
            }
        } else if (footer.cancelled) {
            state.name_dialog_open = false;
            state.validation_error.clear();
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    if (state.delete_dialog_open && design::begin_dialog("##project_explorer_delete",
            "Delete Workspace Item", ImVec2(560.0f, 250.0f), ImVec2(400.0f, 220.0f))) {
        const bool batch = state.sources.size() > 1;
        design::text(design::text_role_t::title, batch
            ? "Delete these workspace items permanently?"
            : "Delete this workspace item permanently?");
        if (batch) {
            ImGui::TextWrapped("Exact retained selection: %zu items", state.sources.size());
            const std::size_t preview_count = (std::min)(state.sources.size(), std::size_t{8});
            for (std::size_t index = 0; index < preview_count; ++index)
                ImGui::BulletText("%s", state.sources[index].path.c_str());
            if (state.sources.size() > preview_count)
                ImGui::TextDisabled("... and %zu more selected items", state.sources.size() - preview_count);
        } else {
            ImGui::TextWrapped("Target: %s", state.source.c_str());
        }
        ImGui::TextWrapped("This operation is not sent to the Recycle Bin and cannot be undone by AiDA. Every selected folder includes all of its children.");
        const auto footer = design::dialog_footer("project-explorer-delete-footer",
            "Delete Permanently", true, true);
        if (footer.confirmed) {
            const auto queued = batch
                ? submit_batch_file_operation(file_operation_t::remove, state.sources)
                : submit_file_operation(file_operation_t::remove,
                    path_from_utf8(state.source), {}, state.source_directory);
            if (queued.accepted) {
                state.delete_dialog_open = false;
                ImGui::CloseCurrentPopup();
            } else {
                state.operation_error = queued.detail;
            }
        } else if (footer.cancelled) {
            state.delete_dialog_open = false;
            ImGui::CloseCurrentPopup();
        }
        if (!state.operation_error.empty())
            design::text(design::text_role_t::caption, state.operation_error.c_str());
        ImGui::EndPopup();
    }
    ImGui::End();
}

bool can_restore_previous_session() {
	const auto& paths = recent_workspace_paths();
    return previous_closed_session(paths) != nullptr;
}

bool request_restore_previous_session() {
	const auto& paths = recent_workspace_paths();
    const std::string* path = previous_closed_session(paths);
    if (!path)
        return false;
    request_recent_open(*path);
    return true;
}

void render_start_center() {
    g_render_section = "registry_start_center";
    const auto metrics = design::metrics();
    const float minimum_width = aida::ui::scale_px(320.0f, metrics.scale);
    const ImVec2 available = ImGui::GetContentRegionAvail();
    if (design::tiny_view_required(available, ImVec2(minimum_width,
            aida::ui::scale_px(260.0f, metrics.scale)))) {
        const design::action_t actions[] = {
            {"open-binary", "Open Binary", nullptr, "Open a binary analysis session", nullptr,
                nullptr, components::button_kind_t::primary, true, true, true},
            {"open-file", "Open File", nullptr, "Open a programming or data file", "Ctrl+O",
                nullptr, components::button_kind_t::secondary, true, false, true}
        };
        const design::state_presentation_t state{"start-center-tiny", design::view_state_t::tiny,
            "Start Center", "Widen this dock to show recent sessions, workspace presets and diagnostics.",
            nullptr, nullptr, nullptr, nullptr, "Open Binary or Open File remains available here.",
            -1.0f, 0.0, false, actions, std::size(actions)};
        const auto result = design::render_state(state, available);
        if (result.invoked && result.id) {
            const char* action = std::strcmp(result.id, "open-binary") == 0
                ? "tools.load_binary" : "file.open";
            static_cast<void>(application_ui::execute_action(action,
                action_invocation_source_t::toolbar));
            application_views::dismiss_start_center_when_work_available();
        }
        return;
    }

    ImGui::BeginChild("##start_center_scroll", ImVec2(0.0f, 0.0f), false,
        ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_NoSavedSettings);
    const design::header_t header{"start-center", "Start Center", "AiDA / Workbench",
        "Ready", "Ctrl+Shift+P", design::semantic_t::brand, nullptr, 0, true};
    static_cast<void>(design::render_view_header(header));
    design::text(design::text_role_t::body,
        "Open analysis and programming work in one dockable reverse-engineering IDE.");
    ImGui::Spacing();

    const float content_width = (std::max)(minimum_width, ImGui::GetContentRegionAvail().x);
    const bool wide = content_width >= aida::ui::scale_px(820.0f, metrics.scale);
    const int columns = wide ? 2 : 1;
    if (ImGui::BeginTable("##start_center_columns", columns,
            ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_BordersInnerV |
            ImGuiTableFlags_PadOuterX)) {
        if (wide) {
            ImGui::TableSetupColumn("##start_primary", ImGuiTableColumnFlags_WidthStretch, 1.15f);
            ImGui::TableSetupColumn("##start_recent", ImGuiTableColumnFlags_WidthStretch, 0.85f);
        }
        ImGui::TableNextColumn();
        render_start_section_label("Start", "analysis, debugging or programming");
        const float action_gap = metrics.spacing_sm;
        const float action_width = wide
            ? (std::max)(aida::ui::scale_px(150.0f, metrics.scale),
                (ImGui::GetContentRegionAvail().x - action_gap) * 0.5f)
            : ImGui::GetContentRegionAvail().x;
        const bool paired = wide && action_width * 2.0f + action_gap <= ImGui::GetContentRegionAvail().x + 1.0f;
        render_start_action("tools.load_binary", "Open Binary...",
            "Open a binary and create an analysis session", action_width);
        if (paired) ImGui::SameLine(0.0f, action_gap);
        render_start_action("file.open_folder", "Open Folder / Source Project...",
            "Open a source or mixed workspace", paired ? action_width : ImGui::GetContentRegionAvail().x);
        render_start_action("tools.attach_process", "Attach to Process...",
            "Attach to a live process", action_width);
        if (paired) ImGui::SameLine(0.0f, action_gap);
        render_start_action("debugger.launch", "Launch Target...",
            "Launch a target under the debugger", paired ? action_width : ImGui::GetContentRegionAvail().x);
        render_start_action("file.restore_previous_session", "Restore Previous Session",
            "Open the most recent closed binary or analysis session", action_width);
        if (paired) ImGui::SameLine(0.0f, action_gap);
        render_start_action("view.manage.view.recent", "Browse All Recent Work",
            "Open the dockable Recent view", paired ? action_width : ImGui::GetContentRegionAvail().x);
        render_start_action("file.new", "New Programming File",
            "Create an untitled code document", action_width);
        if (paired) ImGui::SameLine(0.0f, action_gap);
        render_start_action("file.open", "Open Programming File...",
            "Open a source, script, configuration or data file",
            paired ? action_width : ImGui::GetContentRegionAvail().x);

        ImGui::Spacing();
        render_start_section_label("Workspaces", "task-oriented dock arrangements");
        std::size_t preset_count = 0;
        const auto* presets = workspace_layout::presets(preset_count);
        for (std::size_t index = 0; index < preset_count; ++index) {
            const auto& preset = presets[index];
            if (preset.id == workspace_layout::workspace_preset_t::safe)
                continue;
            std::string action_id = "workspace.switch.";
            action_id.append(preset.stable_id);
            std::string label(preset.display_name);
            if (workspace_layout::active_preset() == preset.id)
                label += "  (Active)";
            render_start_action(action_id.c_str(), label.c_str(),
                std::string(preset.description).c_str(), ImGui::GetContentRegionAvail().x);
        }

        if (wide)
            ImGui::TableNextColumn();
        else {
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
        }
        render_start_section_label("Continue", "recent and open analysis sessions");
		const auto& recent_paths = recent_workspace_paths();
        const std::size_t session_count = analysis_session::session_count();
        bool rendered_recent = false;
        static std::string selected_recent_path;
        static bool selected_recent_open = false;
        bool recent_row_focused = false;
        for (std::size_t index = 0; index < (std::min)(session_count, std::size_t{6}); ++index) {
            const auto session = analysis_session::session_handle_at(index);
            if (!session)
                continue;
            rendered_recent = true;
            ImGui::PushID(static_cast<int>(index));
            const std::string label = (session->filename.empty() ? path_leaf(session->path) : session->filename) +
                "\n" + session->path;
            if (ImGui::Selectable(label.c_str(), index == analysis_session::active_session_idx(),
                    ImGuiSelectableFlags_AllowDoubleClick)) {
                selected_recent_path = session->path;
                selected_recent_open = true;
                analysis_session::switch_session(index);
                application_views::open_or_focus(stable_view_id_t("document.disassembly"));
                application_views::dismiss_start_center_when_work_available();
            }
            if (ImGui::IsItemFocused()) {
                selected_recent_path = session->path;
                selected_recent_open = true;
                recent_row_focused = true;
            }
            design::draw_focus_ring_for_last_item();
            design::tooltip_for_last_item(session->path.c_str(), "Enter");
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
                application_ui::open_recent_context_menu(session->path, true,
                    context_menu_open_origin_t::pointer);
            ImGui::PopID();
        }
        std::size_t closed_count = 0;
        for (const auto& path : recent_paths) {
            if (session_is_open(path))
                continue;
            rendered_recent = true;
            ImGui::PushID(path.c_str());
            const std::string label = path_leaf(path) + "\n" + path;
            if (ImGui::Selectable(label.c_str(), selected_recent_path == path)) {
                selected_recent_path = path;
                selected_recent_open = false;
                request_recent_open(path);
                application_views::dismiss_start_center_when_work_available();
            }
            if (ImGui::IsItemFocused()) {
                selected_recent_path = path;
                selected_recent_open = false;
                recent_row_focused = true;
            }
            design::draw_focus_ring_for_last_item();
            design::tooltip_for_last_item(path.c_str(), "Enter");
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
                application_ui::open_recent_context_menu(path, false,
                    context_menu_open_origin_t::pointer);
            ImGui::PopID();
            if (++closed_count == 8)
                break;
        }
        if (!rendered_recent) {
            const design::state_presentation_t empty{"start-center-recent-empty",
                design::view_state_t::empty, "No recent work",
                "Opened binaries and source workspaces remain available here for quick return.",
                nullptr, nullptr, nullptr, nullptr, "Use Open Binary or Open Folder to begin.",
                -1.0f, 0.0, false, nullptr, 0};
            static_cast<void>(design::render_state(empty,
                ImVec2(0.0f, aida::ui::scale_px(116.0f, metrics.scale))));
        }
        context_menu_open_origin_t recent_origin = context_menu_open_origin_t::pointer;
        if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
            context_key_pressed(recent_origin) && recent_row_focused && !selected_recent_path.empty())
            application_ui::open_recent_context_menu(selected_recent_path,
                selected_recent_open, recent_origin);
        application_ui::render_recent_context_menu();

        ImGui::Spacing();
        render_start_section_label("Recovery and status");
        render_start_action("view.manage.view.background_tasks", "Background Tasks",
            "Review long-running work and exact cancellation capability",
            ImGui::GetContentRegionAvail().x);
        render_start_action("view.manage.view.diagnostics", "Diagnostics",
            "Review persistent failures, stable diagnostic IDs and recovery actions",
            ImGui::GetContentRegionAvail().x);
        render_start_action("tools.settings", "Settings",
            "Configure the IDE without leaving the current workspace",
            ImGui::GetContentRegionAvail().x);
        render_start_action("workspace.safe", "Activate Safe Layout",
            "Recover a broken layout without discarding project or session state",
            ImGui::GetContentRegionAvail().x);
        ImGui::EndTable();
    }
    ImGui::EndChild();
}

void render_project_explorer() {
    g_render_section = "registry_project_explorer";
    auto& presentation = explorer_presentation();
    const auto metrics = design::metrics();
    const ImVec2 available = ImGui::GetContentRegionAvail();
    if (design::tiny_view_required(available,
            ImVec2(aida::ui::scale_px(220.0f, metrics.scale),
                aida::ui::scale_px(150.0f, metrics.scale)))) {
        const design::action_t actions[] = {
            {"open-folder", "Open Folder", nullptr, "Open a Project Explorer root", "Ctrl+K",
                nullptr, components::button_kind_t::primary, true, true, true},
            {"refresh", "Refresh", nullptr, "Refresh the current Project Explorer root", nullptr,
                nullptr, components::button_kind_t::secondary, !file_browser::roots.empty(), false, true}
        };
        const design::state_presentation_t compact{
            "project-explorer.tiny", design::view_state_t::tiny,
            "Project Explorer is too small",
            "Widen, float, or move this dock to restore the filter, tree and complete right-click action catalog.",
            file_browser::current_dir.empty() ? nullptr : file_browser::current_dir.c_str(),
            nullptr, nullptr, nullptr,
            "All Explorer commands remain available through the application menu and command palette.",
            -1.0f, 0.0, false, actions, std::size(actions)
        };
        const auto result = design::render_state(compact, available);
        if (result.invoked && result.id)
            static_cast<void>(application_ui::execute_action(
                std::strcmp(result.id, "open-folder") == 0 ? "file.open_folder" : "explorer.refresh",
                action_invocation_source_t::toolbar));
        return;
    }
    const float toolbar_height = aida::ui::scale_px(36.0f, metrics.scale);
    const design::action_t toolbar_actions[] = {
        {"open-folder", "Open Folder", ICON_FILES_EMPTY, "Open a source, script, or binary workspace folder",
            "Ctrl+K", nullptr, components::button_kind_t::secondary, true, true, true},
        {"refresh", "Refresh", ICON_SPINNER, "Refresh the project tree from disk",
            nullptr, nullptr, components::button_kind_t::ghost, true, false, true},
        {"search", "Search", ICON_SEARCH, "Search files in the open workspace",
            "Ctrl+Shift+F", nullptr, components::button_kind_t::ghost, true, false, true}
    };
    ImGui::BeginChild("##explorer_toolbar", ImVec2(0.0f, toolbar_height), false,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoSavedSettings);
    const auto toolbar_result = design::render_toolbar("project-explorer", toolbar_actions,
        std::size(toolbar_actions), ImGui::GetContentRegionAvail().x);
    if (toolbar_result.invoked && toolbar_result.id) {
        if (std::strcmp(toolbar_result.id, "open-folder") == 0)
            application_ui::execute_action("file.open_folder", action_invocation_source_t::toolbar);
        else if (std::strcmp(toolbar_result.id, "refresh") == 0)
            application_ui::execute_action("explorer.refresh", action_invocation_source_t::toolbar);
        else if (std::strcmp(toolbar_result.id, "search") == 0)
            application_ui::execute_action("explorer.search", action_invocation_source_t::toolbar);
    }
    ImGui::EndChild();

    const float root_height = aida::ui::scale_px(30.0f, metrics.scale);
    const ImVec2 root_origin = ImGui::GetCursorScreenPos();
    const float root_width = (std::max)(1.0f, ImGui::GetContentRegionAvail().x);
    ImDrawList* draw = ImGui::GetWindowDrawList();
    const auto& theme = aida::ui::resolved();
    draw->AddRectFilled(root_origin, ImVec2(root_origin.x + root_width, root_origin.y + root_height),
        theme.bg_elevated);
    draw->AddLine(ImVec2(root_origin.x, root_origin.y + root_height),
        ImVec2(root_origin.x + root_width, root_origin.y + root_height), theme.border_subtle);
    ImGui::InvisibleButton("##project_root", ImVec2(root_width, root_height));
    std::string root_label = file_browser::current_dir.empty()
        ? std::string("No folder open") : path_to_utf8(
            path_from_utf8(file_browser::current_dir).lexically_normal());
    if (file_browser::roots.size() > 1)
        root_label = std::to_string(file_browser::roots.size()) + " workspace roots";
    for (std::size_t offset = 0; (offset = root_label.find('/', offset)) != std::string::npos; offset += 3)
        root_label.replace(offset, 1, " / ");
    const ImVec2 root_text_min(root_origin.x + 9.0f * metrics.scale,
        root_origin.y + (root_height - ImGui::GetFontSize()) * 0.5f);
    const ImVec2 root_text_max(root_origin.x + root_width - 8.0f * metrics.scale,
        root_origin.y + root_height);
    ImGui::RenderTextEllipsis(draw, root_text_min, root_text_max, root_text_max.x,
        root_label.c_str(), nullptr, nullptr);
    design::tooltip_for_last_item(file_browser::current_dir.empty()
        ? "Open a folder to create a programming and reverse-engineering workspace"
        : (file_browser::roots.size() > 1 ? "Each workspace root is indexed independently and remains docked in this Explorer"
                                         : file_browser::current_dir.c_str()));

    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,
        ImVec2(metrics.spacing_sm, aida::ui::scale_px(5.0f, metrics.scale)));
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::GetIO().KeyCtrl && !ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F, false))
        ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::InputTextWithHint("##project_filter", "Filter files and folders",
            presentation.filter, sizeof(presentation.filter)))
        presentation.filter_dirty = true;
    ImGui::PopStyleVar();
    design::tooltip_for_last_item("Filter the visible project tree", "Ctrl+F");
    design::draw_focus_ring_for_last_item();

    if (file_browser::needs_refresh)
        file_browser::refresh();
    const bool indexing = file_browser::index_state == file_browser::index_state_t::loading;
    if (indexing && file_browser::entries.empty()) {
        ImGui::BeginChild("##project_tree", ImVec2(0.0f, (std::max)(1.0f, ImGui::GetContentRegionAvail().y)), false,
            ImGuiWindowFlags_NoSavedSettings);
        const design::action_t cancel_action{
            "cancel", "Cancel", nullptr, "Cancel this project index generation", "Esc",
            nullptr, components::button_kind_t::secondary, true, false, true
        };
        const design::state_presentation_t loading{
            "project-explorer.loading", design::view_state_t::loading,
            "Refreshing project tree", "Reading the workspace hierarchy and preserving expanded folders.",
            file_browser::current_dir.empty() ? nullptr : file_browser::current_dir.c_str(),
            "Enumerating files", nullptr, nullptr, "The editor remains available while the tree refreshes.",
            -1.0f, 0.0, false, &cancel_action, 1
        };
        const auto state_result = design::render_state(loading, ImGui::GetContentRegionAvail());
        if ((state_result.invoked && state_result.id && std::strcmp(state_result.id, "cancel") == 0) ||
            ImGui::IsKeyPressed(ImGuiKey_Escape, false))
            file_browser::cancel_refresh();
        ImGui::EndChild();
        g_render_section = "registry_project_explorer_refresh";
        presentation.filter_dirty = true;
        file_browser::tick_watcher();
        application_ui::render_explorer_context_menu();
        return;
    }
    file_browser::tick_watcher();

    if (presentation.filter_dirty || presentation.applied_filter != presentation.filter ||
        presentation.indexed_root != file_browser::current_dir ||
        presentation.indexed_entry_count != file_browser::entries.size())
        rebuild_explorer_filter(presentation);

    if (file_browser::selected_paths.empty() && file_browser::selected_idx >= 0 &&
        static_cast<std::size_t>(file_browser::selected_idx) < file_browser::entries.size()) {
        const std::string selected = path_key(file_browser::entries[
            static_cast<std::size_t>(file_browser::selected_idx)].full_path);
        if (!selected.empty()) {
            file_browser::selected_paths.insert(selected);
            file_browser::selection_anchor_path = selected;
        }
    }

    int focused_index = -1;
    bool row_context_opened = false;
    const ImVec2 tree_size = ImGui::GetContentRegionAvail();
    ImGui::BeginChild("##project_tree", ImVec2(0.0f, (std::max)(1.0f, tree_size.y)), false,
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_HorizontalScrollbar);
    const bool invalid_root = file_browser::index_state == file_browser::index_state_t::error;
    if (invalid_root) {
        const design::action_t actions[] = {
            {"open-folder", "Open Folder", nullptr, "Choose an accessible workspace folder", "Ctrl+K",
                nullptr, components::button_kind_t::primary, true, true, true},
            {"retry", "Retry", nullptr, "Retry reading the current workspace root", nullptr,
                nullptr, components::button_kind_t::secondary, true, false, true}
        };
        const design::state_presentation_t state{
            "project-explorer.error", design::view_state_t::error,
            "Workspace folder is unavailable",
            "The saved project root could not be read. Select another folder or retry after restoring access.",
            file_browser::current_dir.c_str(), "Project tree refresh", "EXPLORER_ROOT_UNAVAILABLE",
            nullptr, "The current editor documents remain open.", -1.0f, 0.0, true,
            actions, std::size(actions)
        };
        const auto result = design::render_state(state, ImGui::GetContentRegionAvail());
        if (!file_browser::index_error.empty() && ImGui::IsWindowHovered())
            ImGui::SetTooltip("%s", file_browser::index_error.c_str());
        if (result.invoked && result.id) {
            if (std::strcmp(result.id, "open-folder") == 0)
                application_ui::execute_action("file.open_folder", action_invocation_source_t::toolbar);
            else if (std::strcmp(result.id, "retry") == 0)
                application_ui::execute_action("explorer.refresh", action_invocation_source_t::toolbar);
        }
    } else if (file_browser::index_state == file_browser::index_state_t::cancelled &&
            file_browser::entries.empty()) {
        const design::action_t retry_action{
            "retry", "Refresh", nullptr, "Restart project indexing", nullptr,
            nullptr, components::button_kind_t::primary, true, true, true
        };
        const design::state_presentation_t state{
            "project-explorer.cancelled", design::view_state_t::empty,
            "Project refresh cancelled", "The previous project-tree generation was cancelled safely.",
            file_browser::current_dir.empty() ? nullptr : file_browser::current_dir.c_str(),
            "Project tree refresh", nullptr, nullptr,
            "Open editor documents were not affected.", -1.0f, 0.0, false,
            &retry_action, 1
        };
        const auto result = design::render_state(state, ImGui::GetContentRegionAvail());
        if (result.invoked)
            application_ui::execute_action("explorer.refresh", action_invocation_source_t::toolbar);
    } else if (file_browser::entries.empty() ||
            (presentation.filter[0] != '\0' && presentation.visible_indices.empty())) {
        const bool no_root = file_browser::current_dir.empty();
        const bool no_results = !no_root && presentation.filter[0] != '\0';
        const design::action_t open_action{
            "open-folder", "Open Folder", nullptr, "Choose a project workspace folder", "Ctrl+K",
            nullptr, components::button_kind_t::primary, true, true, no_root
        };
        const design::state_presentation_t state{
            no_results ? "project-explorer.no-results" :
                (no_root ? "project-explorer.no-root" : "project-explorer.empty"),
            design::view_state_t::empty,
            no_results ? "No matching project items" : (no_root ? "Open a workspace folder" : "This folder is empty"),
            no_results ? "Adjust or clear the filter to restore the complete project tree." :
                (no_root ? "Browse source files, scripts, binaries, symbols, and project artifacts in one tree." :
                    "The selected workspace root contains no visible files or folders."),
            no_root ? nullptr : file_browser::current_dir.c_str(), nullptr, nullptr, nullptr,
            no_results ? "Press Ctrl+F to edit the filter." : "You can also open binaries directly from the File menu.",
            -1.0f, 0.0, false, no_root ? &open_action : nullptr, no_root ? 1u : 0u
        };
        const auto result = design::render_state(state, ImGui::GetContentRegionAvail());
        if (result.invoked)
            application_ui::execute_action("file.open_folder", action_invocation_source_t::toolbar);
    } else {
        if (indexing) {
            ImGui::TextDisabled("Indexing... %zu folders, %zu items",
                file_browser::indexed_directory_count, file_browser::indexed_entry_count);
            ImGui::SameLine();
            if (ImGui::SmallButton("Cancel"))
                file_browser::cancel_refresh();
        } else if (file_browser::index_truncated) {
            ImGui::TextDisabled("Project tree reached its bounded indexing limit; narrow the workspace roots.");
        }
        if (!file_browser::index_error.empty()) {
            ImGui::TextDisabled("Some workspace locations could not be indexed. Hover for details.");
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", file_browser::index_error.c_str());
        }
        if (file_browser::selected_paths.size() > 1)
            ImGui::TextDisabled("%zu items selected", file_browser::selected_paths.size());
        if (!file_browser::selection_error.empty()) {
            ImGui::TextDisabled("%s", file_browser::selection_error.c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Use Ctrl+click or a smaller Shift+click range to continue.");
        }
        const float row_height = aida::ui::scale_px(24.0f, metrics.scale);
        const bool filtered = presentation.filter[0] != '\0';
        const int count = filtered ? static_cast<int>(presentation.visible_indices.size()) :
            static_cast<int>(file_browser::entries.size());
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 0.0f));
        ImGuiListClipper clipper;
        clipper.Begin(count, row_height);
        while (clipper.Step()) {
            for (int visible_index = clipper.DisplayStart; visible_index < clipper.DisplayEnd; ++visible_index) {
                const int source_index = filtered ? presentation.visible_indices[static_cast<std::size_t>(visible_index)] :
                    visible_index;
                render_explorer_row(source_index, row_height, metrics.scale, focused_index, row_context_opened);
                if (presentation.filter_dirty)
                    break;
            }
            if (presentation.filter_dirty)
                break;
        }
        ImGui::PopStyleVar();
    }

    context_menu_open_origin_t origin = context_menu_open_origin_t::pointer;
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && context_key_pressed(origin)) {
        const int index = focused_index >= 0 ? focused_index : file_browser::selected_idx;
        if (index >= 0 && static_cast<std::size_t>(index) < file_browser::entries.size()) {
            if (!explorer_path_selected(file_browser::entries[
                    static_cast<std::size_t>(index)].full_path))
                replace_explorer_selection(index);
            application_ui::open_explorer_context_menu(index, origin);
        } else
            application_ui::open_explorer_empty_context_menu(origin);
    }
    if (!row_context_opened && ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByPopup) &&
        !ImGui::IsAnyItemHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Right))
        application_ui::open_explorer_empty_context_menu(context_menu_open_origin_t::pointer);
    ImGui::EndChild();
    application_ui::render_explorer_context_menu();
}

void render_workspace_search() {
    g_render_section = "registry_workspace_search";
    ImGui::SetNextItemWidth(-1.0f);
    const bool submitted = ImGui::InputTextWithHint("##workspace_search_query", "Search workspace",
        workspace_search::g_search.query_buf, sizeof(workspace_search::g_search.query_buf),
        ImGuiInputTextFlags_EnterReturnsTrue);
    if (submitted)
        start_workspace_search();

    ImGui::Checkbox("Match case", &workspace_search::g_search.case_sensitive);
    ImGui::SameLine();
    ImGui::Checkbox("Whole word", &workspace_search::g_search.whole_word);
    ImGui::SameLine();
    ImGui::Checkbox("Regex", &workspace_search::g_search.use_regex);
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##workspace_search_include", "Files to include, for example *.cpp,*.h",
        workspace_search::g_search.include_buf, sizeof(workspace_search::g_search.include_buf));
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##workspace_search_exclude", "Files to exclude, for example build,*_generated.h",
        workspace_search::g_search.exclude_buf, sizeof(workspace_search::g_search.exclude_buf));

    const bool searching = workspace_search::g_search.searching.load(std::memory_order_acquire);
    const bool search_truncated = workspace_search::g_search.truncated.load(std::memory_order_acquire);
    if (searching) {
        ImGui::Text("Searching... %d files, %d matches",
            workspace_search::g_search.files_scanned.load(std::memory_order_acquire),
            workspace_search::g_search.match_count.load(std::memory_order_acquire));
        ImGui::SameLine();
        if (ImGui::Button("Cancel"))
            workspace_search::g_search.cancel.store(true, std::memory_order_release);
    } else {
        if (ImGui::Button("Search"))
            start_workspace_search();
    }
    ImGui::Separator();

    std::vector<std::pair<int, workspace_search::match_result_t>> results;
    {
        std::lock_guard<std::mutex> lock(workspace_search::g_search.results_mtx);
        const std::size_t count = (std::min)(workspace_search::g_search.results.size(), std::size_t{500});
        results.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            results.emplace_back(static_cast<int>(index), workspace_search::g_search.results[index]);
    }
    if (results.empty()) {
        if (searching)
            ImGui::TextDisabled("Results will appear as matching files are scanned.");
        else if (workspace_search::g_search.query_buf[0] == '\0')
            ImGui::TextDisabled("Enter text to search the open workspace.");
        else if (search_truncated)
            ImGui::TextDisabled("No matches were found before the bounded workspace-search limit was reached.");
        else
            ImGui::TextDisabled("No matches were found.");
        return;
    }

    const bool presentation_capped = workspace_search::g_search.match_count.load(std::memory_order_acquire) > 500;
    ImGui::TextDisabled("%zu result%s%s%s", results.size(), results.size() == 1 ? "" : "s",
        presentation_capped ? " (first 500 shown)" : "",
        search_truncated ? " (bounded search limit reached)" : "");
    int focused_index = -1;
    std::size_t group_start = 0;
    while (group_start < results.size()) {
        const std::string& filepath = results[group_start].second.filepath;
        std::size_t group_end = group_start + 1;
        while (group_end < results.size() && results[group_end].second.filepath == filepath)
            ++group_end;
        ImGui::PushID(filepath.c_str());
        const std::string group_label = path_leaf(filepath) + " (" +
            std::to_string(group_end - group_start) + ")";
        const bool group_open = ImGui::TreeNodeEx("##workspace_search_group",
            ImGuiTreeNodeFlags_DefaultOpen | ImGuiTreeNodeFlags_SpanAvailWidth,
            "%s", group_label.c_str());
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", filepath.c_str());
        if (group_open) {
            for (std::size_t result_index = group_start; result_index < group_end; ++result_index) {
                const int source_index = results[result_index].first;
                const auto& result = results[result_index].second;
                ImGui::PushID(source_index);
                const std::string label = std::to_string(result.line_number) + ": " + result.line_text;
                if (ImGui::Selectable(label.c_str(), workspace_search::g_search.selected_idx == source_index)) {
                    workspace_search::g_search.selected_idx = source_index;
                    open_search_result(result);
                }
                if (ImGui::IsItemFocused())
                    focused_index = source_index;
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    workspace_search::g_search.selected_idx = source_index;
                    application_ui::open_workspace_search_context_menu(source_index,
                        context_menu_open_origin_t::pointer);
                }
                ImGui::PopID();
            }
            ImGui::TreePop();
        }
        ImGui::PopID();
        group_start = group_end;
    }
    context_menu_open_origin_t origin = context_menu_open_origin_t::pointer;
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && context_key_pressed(origin)) {
        const int index = focused_index >= 0 ? focused_index : workspace_search::g_search.selected_idx;
        if (index >= 0)
            application_ui::open_workspace_search_context_menu(index, origin);
    }
    application_ui::render_workspace_search_context_menu();
}

void render_recent() {
    g_render_section = "registry_recent";
    std::vector<std::string> recent_paths;
    if (!g_sa_settings.recent_workspaces_json.empty()) {
        const auto json = nlohmann::json::parse(g_sa_settings.recent_workspaces_json, nullptr, false);
        if (!json.is_discarded() && json.is_array()) {
            for (const auto& value : json)
                if (value.is_string())
                    recent_paths.push_back(value.get<std::string>());
        }
    }

    const std::size_t open_count = analysis_session::session_count();
    const std::size_t active_index = analysis_session::active_session_idx();
    std::unordered_set<std::string> open_paths;
    bool any = false;
    std::optional<std::size_t> close_requested;
    static std::string selected_path;
    static bool selected_open = false;
    bool focused_row = false;

    if (open_count != 0) {
        ImGui::SeparatorText("Open Binaries");
        for (std::size_t index = 0; index < open_count; ++index) {
            const auto session = analysis_session::session_handle_at(index);
            if (!session)
                continue;
            any = true;
            open_paths.insert(path_key(session->path));
            ImGui::PushID(static_cast<int>(index));
            const std::string label = (session->filename.empty() ? path_leaf(session->path) : session->filename) +
                "\n" + session->path;
            const float row_width = (std::max)(1.0f, ImGui::GetContentRegionAvail().x - 54.0f);
            if (ImGui::Selectable(label.c_str(), index == active_index || selected_path == session->path,
                    ImGuiSelectableFlags_AllowDoubleClick, ImVec2(row_width, 0.0f))) {
                selected_path = session->path;
                selected_open = true;
                analysis_session::switch_session(index);
            }
            if (ImGui::IsItemFocused()) {
                selected_path = session->path;
                selected_open = true;
                focused_row = true;
            }
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                selected_path = session->path;
                selected_open = true;
                application_ui::open_recent_context_menu(session->path, true,
                    context_menu_open_origin_t::pointer);
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", session->path.c_str());
            ImGui::SameLine();
            if (ImGui::SmallButton("Close"))
                close_requested = index;
            ImGui::PopID();
        }
        if (close_requested)
            analysis_session::close_session(*close_requested);
    }

    std::vector<std::string> closed_paths;
    for (const auto& path : recent_paths) {
        if (open_paths.find(path_key(path)) == open_paths.end())
            closed_paths.push_back(path);
        if (closed_paths.size() == 10)
            break;
    }
    if (!closed_paths.empty()) {
        ImGui::SeparatorText("Recent (Closed)");
        for (std::size_t index = 0; index < closed_paths.size(); ++index) {
            const auto& path = closed_paths[index];
            any = true;
            ImGui::PushID(static_cast<int>(open_count + index));
            const std::string label = path_leaf(path) + "\n" + path;
            if (ImGui::Selectable(label.c_str(), selected_path == path)) {
                selected_path = path;
                selected_open = false;
                request_recent_open(path);
            }
            if (ImGui::IsItemFocused()) {
                selected_path = path;
                selected_open = false;
                focused_row = true;
            }
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                selected_path = path;
                selected_open = false;
                application_ui::open_recent_context_menu(path, false,
                    context_menu_open_origin_t::pointer);
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", path.c_str());
            ImGui::PopID();
        }
    }

    if (!any) {
        ImGui::TextDisabled("No recent binaries.");
        ImGui::TextWrapped("Open a binary from Project Explorer. Open and closed sessions will remain discoverable here.");
    }

    context_menu_open_origin_t origin = context_menu_open_origin_t::pointer;
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && context_key_pressed(origin) &&
        (!selected_path.empty() || focused_row))
        application_ui::open_recent_context_menu(selected_path, selected_open, origin);
    application_ui::render_recent_context_menu();
}

void render_sessions() {
    g_render_section = "registry_sessions";
    if (ImGui::Button("Open Binary..."))
        application_ui::execute_action("file.open", action_invocation_source_t::toolbar);
    ImGui::SameLine();
    if (ImGui::Button("Attach..."))
        application_ui::execute_action("tools.attach_process", action_invocation_source_t::toolbar);
    ImGui::SameLine();
    if (ImGui::Button("Run..."))
        application_ui::execute_action("debugger.launch", action_invocation_source_t::toolbar);
    ImGui::Separator();

    const std::size_t count = analysis_session::session_count();
    const std::size_t active = analysis_session::active_session_idx();
    static std::string selected_path;
    static bool selected_open = false;
    bool focused_row = false;
    std::optional<std::size_t> close_requested;
    for (std::size_t index = 0; index < count; ++index) {
        const auto session = analysis_session::session_handle_at(index);
        if (!session)
            continue;
        ImGui::PushID(static_cast<int>(index));
        const std::string name = session->filename.empty()
            ? path_leaf(session->path) : session->filename;
        std::string label = name.empty() ? "Untitled session" : name;
        if (session->attached_pid != 0)
            label += "  ·  PID " + std::to_string(session->attached_pid);
        label += "\n" + (session->path.empty() ? session->session_name : session->path);
        const float row_width = (std::max)(1.0f, ImGui::GetContentRegionAvail().x - 54.0f);
        if (ImGui::Selectable(label.c_str(), index == active || selected_path == session->path,
                ImGuiSelectableFlags_AllowDoubleClick, ImVec2(row_width, 0.0f))) {
            selected_path = session->path;
            selected_open = true;
            analysis_session::switch_session(index);
        }
        if (ImGui::IsItemFocused()) {
            selected_path = session->path;
            selected_open = true;
            focused_row = true;
        }
        if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
            selected_path = session->path;
            selected_open = true;
            application_ui::open_recent_context_menu(session->path, true,
                context_menu_open_origin_t::pointer);
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", session->path.empty() ? session->session_name.c_str() : session->path.c_str());
        ImGui::SameLine();
        if (ImGui::SmallButton("Close"))
            close_requested = index;
        ImGui::PopID();
    }
    if (close_requested)
        analysis_session::close_session(*close_requested);
    if (count == 0) {
        ImGui::TextDisabled("No open sessions.");
        ImGui::TextWrapped("Open a binary, attach to a process, or launch a target to create a session.");
    }

    context_menu_open_origin_t origin = context_menu_open_origin_t::pointer;
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && context_key_pressed(origin) &&
        (!selected_path.empty() || focused_row))
        application_ui::open_recent_context_menu(selected_path, selected_open, origin);
    application_ui::render_recent_context_menu();
}

}
