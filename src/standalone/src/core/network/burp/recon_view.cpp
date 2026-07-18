#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#endif

#ifdef small
#undef small
#endif

#include "recon_view.hpp"
#include "burp_ui_operation.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_routed.hpp"
#else
#include "crawler.hpp"
#include "content_discovery.hpp"
#include "subdomain_enum.hpp"
#include "payload_library.hpp"
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/components.hpp"
#include "../../ui/design_system.hpp"
#include "../../ui/toast_notification.hpp"
#include "../../ui/application_view_registry.hpp"
#include "../../ui/task_center.hpp"
#include "../../ui/ui_thread_dispatcher.hpp"
#include "../../infra/executor.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_services.hpp"
#else
#include "helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <cstring>
#include <exception>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace aida {
namespace burp {
namespace recon_view {

namespace {

enum class tab_t : int
{
    crawler = 0,
    content_discovery = 1,
    subdomains = 2,
    payloads = 3
};

struct ui_state_t
{
    std::atomic<bool>            initialized{false};
    std::atomic<bool>            initialization_requested{false};
    bool                         initialization_attempted = false;
    int                          active_tab = 0;

    char                         crawler_seed[2048] = "https://example.com/";
    int                          crawler_max_depth = 3;
    int                          crawler_max_pages = 500;
    int                          crawler_concurrency = 8;
    int                          crawler_rate_per_host = 10;
    bool                         crawler_same_host = true;
    bool                         crawler_scope_only = false;
    bool                         crawler_respect_robots = true;
    bool                         crawler_parse_js = true;
    char                         crawler_user_agent[256] = "AiDA-Crawler/1.0";
    char                         crawler_exclude_ext[512] = ".png,.jpg,.jpeg,.gif,.svg,.ico,.woff,.woff2,.ttf,.eot,.css,.mp4,.webm,.mp3,.pdf";
    uint64_t                     crawler_selected = 0;

    char                         disc_target[1024] = "https://example.com/FUZZ";
    char                         disc_wordlist_id[128] = "dirs/common-100";
    char                         disc_extensions[256] = "";
    char                         disc_match_status[128] = "200,201,204,301,302,401,403,500";
    char                         disc_filter_status[128] = "404";
    int                          disc_concurrency = 25;
    int                          disc_delay_ms = 0;
    int                          disc_recurse_depth = 1;
    bool                         disc_recurse = false;
    bool                         disc_auto_calibrate = true;
    bool                         disc_follow_redir = false;
    char                         disc_cookie[1024] = "";
    char                         disc_user_agent[256] = "AiDA-ContentDiscovery/1.0";
    uint64_t                     disc_selected = 0;

    char                         sub_domain[256] = "example.com";
    char                         sub_wordlist_id[128] = "subdomains/top1000";
    int                          sub_concurrency = 32;
    bool                         sub_run_passive = true;
    bool                         sub_run_brute = true;
    bool                         sub_passive_crtsh = true;
    bool                         sub_passive_bufferover = true;
    bool                         sub_passive_hackertarget = true;
    uint64_t                     sub_selected = 0;
    std::atomic<bool>            sub_export_pending{false};
    std::shared_ptr<const std::vector<crawler::crawl_status_t>> crawler_runs =
        std::make_shared<const std::vector<crawler::crawl_status_t>>();
    std::shared_ptr<const std::vector<content_discovery::disc_status_t>> discovery_runs =
        std::make_shared<const std::vector<content_discovery::disc_status_t>>();
    std::shared_ptr<const std::vector<subdomain_enum::enum_status_t>> subdomain_runs =
        std::make_shared<const std::vector<subdomain_enum::enum_status_t>>();
    std::atomic<bool>            refresh_pending{false};
    std::uint64_t                last_refresh_ms = 0;
    std::atomic<std::uint64_t>   started_run_id{0};
    std::atomic<int>             started_run_domain{0};
    std::shared_ptr<const std::vector<payloads::payload_set_t>> payload_sets =
        std::make_shared<const std::vector<payloads::payload_set_t>>();
    aida::burp::ui_operation::state_t operation;
    std::uint64_t                observed_operation_generation = 0;
    int                          review_domain = 0;
    std::uint64_t                reviewed_id = 0;
    std::uint64_t                reviewed_started_ms = 0;
    bool                         awaiting_remove_completion = false;
    std::string                  reviewed_payload_id;
    bool                         reviewed_payload_builtin = false;
    bool                         awaiting_payload_remove_completion = false;
    bool                         clear_payload_inputs_after_success = false;

    char                         pl_filter[128] = "";
    char                         pl_selected_id[128] = "";
    char                         pl_new_id[128] = "";
    char                         pl_new_label[128] = "";
    char                         pl_new_desc[256] = "";
    char                         pl_new_entries[4096] = "";

    std::mutex                   mtx;
};

ui_state_t& ui() { static ui_state_t s; return s; }

void request_run_refresh()
{
    auto& state = ui();
    bool expected = false;
    if (!state.refresh_pending.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel))
        return;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "burp.recon";
    submission.label = "recon.refresh_runs";
    submission.thread_class = "bounded_task";
    submission.domain = aida::infra::executor::domain_t::external_tool;
    submission.priority = 4;
    submission.body = []() {
        auto finish_pending = std::unique_ptr<void, void(*)(void*)>(
            reinterpret_cast<void*>(1), [](void*) {
                ui().refresh_pending.store(false, std::memory_order_release);
            });
        std::shared_ptr<const std::vector<crawler::crawl_status_t>> crawls =
            std::make_shared<const std::vector<crawler::crawl_status_t>>(crawler::list());
        std::shared_ptr<const std::vector<content_discovery::disc_status_t>> discoveries =
            std::make_shared<const std::vector<content_discovery::disc_status_t>>(content_discovery::list());
        std::shared_ptr<const std::vector<subdomain_enum::enum_status_t>> subdomains =
            std::make_shared<const std::vector<subdomain_enum::enum_status_t>>(subdomain_enum::list());
        auto payload_values = payloads::list_summaries();
        for (auto& set : payload_values)
            set.entries = payloads::entries(set.id);
        std::shared_ptr<const std::vector<payloads::payload_set_t>> payload_sets =
            std::make_shared<const std::vector<payloads::payload_set_t>>(std::move(payload_values));
        std::atomic_store_explicit(&ui().crawler_runs, std::move(crawls), std::memory_order_release);
        std::atomic_store_explicit(&ui().discovery_runs, std::move(discoveries), std::memory_order_release);
        std::atomic_store_explicit(&ui().subdomain_runs, std::move(subdomains), std::memory_order_release);
        std::atomic_store_explicit(&ui().payload_sets, std::move(payload_sets), std::memory_order_release);
    };
    if (!aida::infra::executor::submit(std::move(submission)).submitted)
        state.refresh_pending.store(false, std::memory_order_release);
}

template <typename Status>
const Status* find_run(const std::vector<Status>& runs, std::uint64_t id)
{
    const auto found = std::find_if(runs.begin(), runs.end(), [id](const Status& run) {
        return run.id == id;
    });
    return found == runs.end() ? nullptr : &*found;
}

bool submit_recon_operation(std::string action, std::string label,
    std::string target, std::function<aida::burp::ui_operation::result_t()> execute)
{
    aida::burp::ui_operation::request_t request;
    request.owner = "burp.recon";
    request.owner_view = "view.network.recon";
    request.owner_action = std::move(action);
    request.label = std::move(label);
    request.target = std::move(target);
    request.affected_entity = request.target;
    request.execute = std::move(execute);
    return ui().operation.submit(std::move(request));
}

void submit_initialization()
{
    bool expected = false;
    if (!ui().initialization_requested.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel))
        return;
    if (!submit_recon_operation("network.recon.initialize", "Load Recon state",
        "Recon catalogs", []() {
        aida::burp::ui_operation::result_t result;
        result.success = initialize();
        result.message = result.success ? "Recon state loaded." : "Recon initialization failed.";
        return result;
    }))
        ui().initialization_requested.store(false, std::memory_order_release);
}

bool submit_reviewed_remove(int domain, std::uint64_t id, std::uint64_t started_ms)
{
    return submit_recon_operation("network.recon.remove", "Remove Recon run",
        "Run " + std::to_string(id), [domain, id, started_ms]() {
        aida::burp::ui_operation::result_t result;
        bool identity_matches = false;
        if (domain == 1) identity_matches = crawler::status(id).started_unix_ms == started_ms;
        else if (domain == 2) identity_matches = content_discovery::status(id).started_unix_ms == started_ms;
        else if (domain == 3) identity_matches = subdomain_enum::status(id).started_unix_ms == started_ms;
        if (!identity_matches) {
            result.message = "The Recon run changed after review; no run was removed.";
            return result;
        }
        result.success = domain == 1 ? crawler::remove(id) :
            domain == 2 ? content_discovery::remove(id) : subdomain_enum::remove(id);
        result.message = result.success ? "Recon run removed." : "Recon run removal failed.";
        return result;
    });
}

void submit_stop(int domain, std::uint64_t id, std::uint64_t started_ms)
{
    submit_recon_operation("network.recon.stop", "Stop Recon run",
        "Run " + std::to_string(id), [domain, id, started_ms]() {
        aida::burp::ui_operation::result_t result;
        bool identity_matches = false;
        if (domain == 1) identity_matches = crawler::status(id).started_unix_ms == started_ms;
        else if (domain == 2) identity_matches = content_discovery::status(id).started_unix_ms == started_ms;
        else if (domain == 3) identity_matches = subdomain_enum::status(id).started_unix_ms == started_ms;
        if (!identity_matches) {
            result.message = "The Recon run changed before stop; no run was stopped.";
            return result;
        }
        result.success = domain == 1 ? crawler::stop(id) :
            domain == 2 ? content_discovery::stop(id) : subdomain_enum::stop(id);
        result.message = result.success ? "Recon run stop requested." : "Recon run stop failed.";
        return result;
    });
}

void request_remove_review(int domain, std::uint64_t id, std::uint64_t started_ms)
{
    auto& state = ui();
    state.review_domain = domain;
    state.reviewed_id = id;
    state.reviewed_started_ms = started_ms;
    ImGui::OpenPopup("Review Recon removal");
}

bool submit_payload_add(std::string id, std::string label, std::string description,
    std::vector<std::string> entries)
{
    return submit_recon_operation("network.recon.payload.add", "Add payload set", id,
        [id = std::move(id), label = std::move(label), description = std::move(description),
         entries = std::move(entries)]() {
        aida::burp::ui_operation::result_t result;
        result.success = payloads::add_custom_set(id, label, description, entries);
        result.message = result.success ? "Payload set added." : payloads::last_error();
        return result;
    });
}

bool submit_payload_remove(std::string id, bool reviewed_builtin)
{
    return submit_recon_operation("network.recon.payload.remove", "Remove payload set", id,
        [id = std::move(id), reviewed_builtin]() {
        aida::burp::ui_operation::result_t result;
        const auto summaries = payloads::list_summaries();
        const auto found = std::find_if(summaries.begin(), summaries.end(), [&id](const auto& set) {
            return set.id == id;
        });
        if (found == summaries.end() || found->builtin != reviewed_builtin || found->builtin) {
            result.message = "The payload set changed after review; no set was removed.";
            return result;
        }
        result.success = payloads::remove_custom_set(id);
        result.message = result.success ? "Payload set removed." : payloads::last_error();
        return result;
    });
}

std::vector<std::string> split_csv(const char* s)
{
    std::vector<std::string> out;
    if (!s) return out;
    std::string cur;
    for (const char* p = s; *p; ++p)
    {
        if (*p == ',')
        {
            while (!cur.empty() && (cur.front() == ' ' || cur.front() == '\t')) cur.erase(cur.begin());
            while (!cur.empty() && (cur.back() == ' ' || cur.back() == '\t')) cur.pop_back();
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        }
        else cur.push_back(*p);
    }
    while (!cur.empty() && (cur.front() == ' ' || cur.front() == '\t')) cur.erase(cur.begin());
    while (!cur.empty() && (cur.back() == ' ' || cur.back() == '\t')) cur.pop_back();
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::vector<int> split_csv_ints(const char* s)
{
    std::vector<int> out;
    if (!s) return out;
    std::string cur;
    for (const char* p = s; ; ++p)
    {
        if (*p == ',' || *p == '\0')
        {
            try { if (!cur.empty()) out.push_back(std::stoi(cur)); } catch (...) {}
            cur.clear();
            if (*p == '\0') break;
        }
        else if (*p != ' ' && *p != '\t') cur.push_back(*p);
    }
    return out;
}

const char* crawl_phase_label(crawler::crawl_status_phase_t p)
{
    switch (p)
    {
        case crawler::crawl_status_phase_t::pending: return "pending";
        case crawler::crawl_status_phase_t::running: return "running";
        case crawler::crawl_status_phase_t::stopping: return "stopping";
        case crawler::crawl_status_phase_t::complete: return "complete";
        case crawler::crawl_status_phase_t::error: return "error";
    }
    return "?";
}

const char* disc_phase_label(content_discovery::disc_phase_t p)
{
    switch (p)
    {
        case content_discovery::disc_phase_t::pending: return "pending";
        case content_discovery::disc_phase_t::calibrating: return "calibrating";
        case content_discovery::disc_phase_t::running: return "running";
        case content_discovery::disc_phase_t::stopping: return "stopping";
        case content_discovery::disc_phase_t::complete: return "complete";
        case content_discovery::disc_phase_t::error: return "error";
    }
    return "?";
}

const char* sub_phase_label(subdomain_enum::enum_phase_t p)
{
    switch (p)
    {
        case subdomain_enum::enum_phase_t::pending: return "pending";
        case subdomain_enum::enum_phase_t::passive: return "passive";
        case subdomain_enum::enum_phase_t::brute: return "brute";
        case subdomain_enum::enum_phase_t::stopping: return "stopping";
        case subdomain_enum::enum_phase_t::complete: return "complete";
        case subdomain_enum::enum_phase_t::error: return "error";
    }
    return "?";
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
std::string win32_error_text(const char* operation, DWORD error)
{
    return std::string(operation) + " failed with Win32 error " + std::to_string(error);
}

std::filesystem::path subdomain_export_path(uint64_t run_id)
{
    PWSTR known = nullptr;
    std::filesystem::path directory;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &known)) && known)
        directory.assign(known);
    if (known)
        CoTaskMemFree(known);
    if (directory.empty())
        directory = L"C:\\Users\\Public\\Downloads";
    return directory / (L"subdomains_" + std::to_wstring(run_id) + L".csv");
}

bool write_export_atomically(const std::filesystem::path& destination,
                             std::string_view bytes, std::string& error)
{
    if (destination.empty()) {
        error = "The export destination is empty";
        return false;
    }
    std::error_code filesystem_error;
    const auto directory = destination.parent_path();
    if (!directory.empty()) {
        std::filesystem::create_directories(directory, filesystem_error);
        if (filesystem_error) {
            error = "Creating the export directory failed: " + filesystem_error.message();
            return false;
        }
    }
    static std::atomic<std::uint64_t> sequence{1};
    const auto temporary = std::filesystem::path(destination.wstring() + L".tmp." +
        std::to_wstring(GetCurrentProcessId()) + L"." +
        std::to_wstring(GetCurrentThreadId()) + L"." +
        std::to_wstring(sequence.fetch_add(1, std::memory_order_relaxed)));
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = win32_error_text("Creating the export temporary file", GetLastError());
        return false;
    }
    bool succeeded = true;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const DWORD chunk = static_cast<DWORD>((std::min)(bytes.size() - offset,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!WriteFile(file, bytes.data() + offset, chunk, &written, nullptr)) {
            error = win32_error_text("Writing the export temporary file", GetLastError());
            succeeded = false;
            break;
        }
        if (written != chunk) {
            error = "Writing the export temporary file completed with a short write";
            succeeded = false;
            break;
        }
        offset += written;
    }
    if (succeeded && !FlushFileBuffers(file)) {
        error = win32_error_text("Flushing the export temporary file", GetLastError());
        succeeded = false;
    }
    LARGE_INTEGER size{};
    if (succeeded && (!GetFileSizeEx(file, &size) ||
        size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) != bytes.size())) {
        error = "The export temporary file size did not match the requested payload";
        succeeded = false;
    }
    if (!CloseHandle(file) && succeeded) {
        error = win32_error_text("Closing the export temporary file", GetLastError());
        succeeded = false;
    }
    if (succeeded && !MoveFileExW(temporary.c_str(), destination.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        error = win32_error_text("Replacing the export destination", GetLastError());
        succeeded = false;
    }
    if (!succeeded)
        std::filesystem::remove(temporary, filesystem_error);
    return succeeded;
}

bool queue_subdomain_export(uint64_t run_id)
{
    auto& state = ui();
    bool expected = false;
    if (!state.sub_export_pending.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel))
        return false;
    static std::atomic<std::uint64_t> sequence{1};
    const std::string task_id = "network.recon.subdomain_export." +
        std::to_string(run_id) + "." +
        std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
    aida::ui::task_center::task_registration_t registration;
    registration.id = task_id;
    registration.source = "network.recon";
    registration.owner = "Recon";
    registration.owner_view = "view.network.recon";
    registration.owner_action = "network.recon.export_subdomains";
    registration.target = "subdomain run " + std::to_string(run_id);
    registration.label = "Export subdomain results";
    registration.stage = "Queued for bounded snapshot and atomic export";
    registration.affected_entity = registration.target;
    registration.callbacks.focus = [] {
        static_cast<void>(aida::ui_thread::post([] {
            static_cast<void>(aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("view.network.recon")));
        }, "network_recon", "focus_subdomain_export", "task_center_callback"));
    };
    registration.callbacks.open_log = registration.callbacks.focus;
    if (!aida::ui::task_center::register_task(std::move(registration))) {
        state.sub_export_pending.store(false, std::memory_order_release);
        return false;
    }
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "network_recon";
    submission.label = "network.recon.export_subdomains";
    submission.thread_class = "bounded_file_io";
    submission.domain = aida::infra::executor::domain_t::external_tool;
    submission.session_id = task_id.c_str();
    submission.target_id = task_id.c_str();
    submission.diagnostic_id = task_id.c_str();
    submission.ui_access_policy = "immutable_snapshots_only";
    submission.failure_policy = "typed_diagnostic";
    submission.shutdown_policy = "drain";
    submission.body = [run_id, task_id] {
        auto finish_pending = std::unique_ptr<void, void(*)(void*)>(
            reinterpret_cast<void*>(1), [](void*) {
                ui().sub_export_pending.store(false, std::memory_order_release);
            });
        try {
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                aida::ui::task_center::task_state_t::running, -1.0f,
                "Creating a bounded immutable CSV snapshot"));
            std::string csv = subdomain_enum::export_csv(run_id);
            constexpr std::size_t maximum_export_bytes = 64U * 1024U * 1024U;
            if (csv.size() > maximum_export_bytes) {
                static_cast<void>(aida::ui::task_center::update_task(task_id,
                    aida::ui::task_center::task_state_t::failed, 1.0f,
                    "CSV snapshot exceeded the export limit",
                    "The generated CSV exceeded the 64 MiB bounded export limit",
                    "diagnostic." + task_id));
                return;
            }
            const auto destination = subdomain_export_path(run_id);
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                aida::ui::task_center::task_state_t::running, -1.0f,
                "Writing a same-directory temporary file"));
            std::string error;
            if (!write_export_atomically(destination, csv, error)) {
                static_cast<void>(aida::ui::task_center::update_task(task_id,
                    aida::ui::task_center::task_state_t::failed, 1.0f,
                    "Atomic CSV export failed", error, "diagnostic." + task_id));
                return;
            }
            ::diag::log_tagged_fmt("recon_v", "sub_enum_csv_exported run=%llu bytes=%zu",
                static_cast<unsigned long long>(run_id), csv.size());
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                aida::ui::task_center::task_state_t::completed, 1.0f,
                "Finished", "Subdomain CSV exported atomically to " +
                destination.u8string()));
        } catch (const std::exception& exception) {
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                aida::ui::task_center::task_state_t::failed, 1.0f,
                "CSV export failed", exception.what(), "diagnostic." + task_id));
        } catch (...) {
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                aida::ui::task_center::task_state_t::failed, 1.0f,
                "CSV export failed", "Unknown export failure", "diagnostic." + task_id));
        }
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        state.sub_export_pending.store(false, std::memory_order_release);
        static_cast<void>(aida::ui::task_center::update_task(task_id,
            aida::ui::task_center::task_state_t::failed, 1.0f,
            "Executor rejected CSV export", submitted.reject_reason,
            "diagnostic." + task_id));
        return false;
    }
    return true;
}
#else
bool queue_subdomain_export(uint64_t run_id)
{
    bool expected = false;
    if (!ui().sub_export_pending.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel))
        return false;
    const bool submitted = submit_recon_operation("network.recon.export_subdomains",
        "Prepare subdomain CSV export", "Run " + std::to_string(run_id), [run_id]() {
        auto finish_pending = std::unique_ptr<void, void(*)(void*)>(
            reinterpret_cast<void*>(1), [](void*) {
                ui().sub_export_pending.store(false, std::memory_order_release);
            });
        aida::burp::ui_operation::result_t result;
        const std::string csv = subdomain_enum::export_csv(run_id);
        if (csv.size() > 64U * 1024U * 1024U) {
            result.message = "The generated CSV exceeded the 64 MiB preview bound.";
            return result;
        }
        const std::string path = "/aida-preview/exports/subdomains_" +
            std::to_string(run_id) + ".csv";
        aida::preview::network::record_receipt("Subdomain CSV export", path);
        result.success = true;
        result.message = "Subdomain CSV export prepared for Studio preview.";
        return result;
    });
    if (!submitted)
        ui().sub_export_pending.store(false, std::memory_order_release);
    return submitted;
}
#endif

void render_crawler(ui_state_t& st, float alpha)
{
    const auto& th = aida::ui::resolved();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Crawler / Spider");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Seed URLs (comma-separated):");
    aida::ui::input_text("##crl_seed", st.crawler_seed, sizeof(st.crawler_seed), "https://target/, https://target/api", false, ImVec2(680.f, 28.f));

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Max depth:");
    ImGui::SameLine();
    aida::ui::input_int("##crl_depth", &st.crawler_max_depth, ImVec2(80.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Max pages:");
    ImGui::SameLine();
    aida::ui::input_int("##crl_maxp", &st.crawler_max_pages, ImVec2(100.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Concurrency:");
    ImGui::SameLine();
    aida::ui::input_int("##crl_conc", &st.crawler_concurrency, ImVec2(80.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "RPS/host:");
    ImGui::SameLine();
    aida::ui::input_int("##crl_rps", &st.crawler_rate_per_host, ImVec2(80.f, 28.f));

    ImGui::Spacing();
    aida::ui::toggle_switch("##crl_sh", &st.crawler_same_host);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Same host only");
    ImGui::SameLine();
    aida::ui::toggle_switch("##crl_scope", &st.crawler_scope_only);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Scope only");
    ImGui::SameLine();
    aida::ui::toggle_switch("##crl_rob", &st.crawler_respect_robots);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "robots.txt");
    ImGui::SameLine();
    aida::ui::toggle_switch("##crl_js", &st.crawler_parse_js);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Parse JS");

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "User-Agent:");
    aida::ui::input_text("##crl_ua", st.crawler_user_agent, sizeof(st.crawler_user_agent), "AiDA-Crawler/1.0", false, ImVec2(420.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Exclude ext:");
    aida::ui::input_text("##crl_ext", st.crawler_exclude_ext, sizeof(st.crawler_exclude_ext), ".png,.jpg,...", false, ImVec2(360.f, 28.f));

    ImGui::Spacing();
    const bool operation_pending = st.operation.pending();
    ImGui::BeginDisabled(operation_pending);
    if (aida::ui::button("Start Crawl", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm))
    {
        crawler::crawl_config_t cfg;
        cfg.start_urls = split_csv(st.crawler_seed);
        cfg.max_depth = std::max(0, st.crawler_max_depth);
        cfg.same_host_only = st.crawler_same_host;
        cfg.scope_only = st.crawler_scope_only;
        cfg.respect_robots_txt = st.crawler_respect_robots;
        cfg.parse_js = st.crawler_parse_js;
        cfg.max_pages = std::max(1, st.crawler_max_pages);
        cfg.concurrency = std::max(1, st.crawler_concurrency);
        cfg.rate_per_host = std::max(1, st.crawler_rate_per_host);
        cfg.user_agent = st.crawler_user_agent;
        cfg.exclude_extensions = split_csv(st.crawler_exclude_ext);
        submit_recon_operation("network.recon.crawler.start", "Start crawl", st.crawler_seed,
            [cfg = std::move(cfg)]() {
            aida::burp::ui_operation::result_t result;
            const std::uint64_t id = crawler::start(cfg);
            result.success = id != 0;
            result.message = result.success ? "Crawl started." : crawler::last_error();
            if (id != 0) {
                ui().started_run_domain.store(1, std::memory_order_release);
                ui().started_run_id.store(id, std::memory_order_release);
            }
            return result;
        });
    }
    ImGui::SameLine();
    if (aida::ui::button("Stop Selected", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm))
    {
        if (st.crawler_selected != 0) {
            const auto crawls = std::atomic_load_explicit(&st.crawler_runs, std::memory_order_acquire);
            if (const auto* run = find_run(*crawls, st.crawler_selected))
                submit_stop(1, run->id, run->started_unix_ms);
        }
    }
    ImGui::SameLine();
    if (aida::ui::button("Remove Selected", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
    {
        if (st.crawler_selected != 0) {
            const auto crawls = std::atomic_load_explicit(&st.crawler_runs, std::memory_order_acquire);
            if (const auto* run = find_run(*crawls, st.crawler_selected))
                request_remove_review(1, run->id, run->started_unix_ms);
        }
    }
    ImGui::EndDisabled();

    ImGui::Spacing();
    const auto crawls = std::atomic_load_explicit(&st.crawler_runs,
        std::memory_order_acquire);
    if (ImGui::BeginTable("##crawls_tbl", 6,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_Resizable,
        ImVec2(0.f, 220.f)))
    {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Phase");
        ImGui::TableSetupColumn("Queue");
        ImGui::TableSetupColumn("Visited");
        ImGui::TableSetupColumn("Failed");
        ImGui::TableSetupColumn("Found");
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(crawls->size()));
        while (clipper.Step())
        for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index)
        {
            const auto& c = (*crawls)[static_cast<std::size_t>(index)];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char buf[32];
            snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(c.id));
            bool sel = (c.id == st.crawler_selected);
            if (ImGui::Selectable(buf, sel, ImGuiSelectableFlags_SpanAllColumns)) st.crawler_selected = c.id;
            ImGui::TableNextColumn(); ImGui::TextUnformatted(crawl_phase_label(c.phase));
            ImGui::TableNextColumn(); ImGui::Text("%d", c.queue_depth);
            ImGui::TableNextColumn(); ImGui::Text("%d", c.pages_visited);
            ImGui::TableNextColumn(); ImGui::Text("%d", c.pages_failed);
            ImGui::TableNextColumn(); ImGui::Text("%d", c.urls_found);
        }
        ImGui::EndTable();
    }

    if (st.crawler_selected != 0)
    {
        const auto* cs = find_run(*crawls, st.crawler_selected);
        if (cs) {
        ImGui::Spacing();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
            "Discovered (%zu) | Last: %s", cs->discovered.size(), cs->last_url.c_str());
        if (ImGui::BeginTable("##disc_urls", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
            ImVec2(0.f, 220.f)))
        {
            ImGui::TableSetupColumn("Status");
            ImGui::TableSetupColumn("Bytes");
            ImGui::TableSetupColumn("Depth");
            ImGui::TableSetupColumn("Content-Type");
            ImGui::TableSetupColumn("URL", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(cs->discovered.size()));
            while (clipper.Step())
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index)
            {
                const auto& d = cs->discovered[static_cast<std::size_t>(index)];
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::Text("%d", d.status);
                ImGui::TableNextColumn(); ImGui::Text("%zu", d.body_bytes);
                ImGui::TableNextColumn(); ImGui::Text("%d", d.depth);
                ImGui::TableNextColumn(); ImGui::TextUnformatted(d.content_type.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(d.url.c_str());
            }
            ImGui::EndTable();
        }
        }
    }
}

void render_content_discovery(ui_state_t& st, float alpha)
{
    const auto& th = aida::ui::resolved();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Content Discovery (ffuf)");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Target URL (use FUZZ marker):");
    aida::ui::input_text("##cd_url", st.disc_target, sizeof(st.disc_target), "https://target/FUZZ", false, ImVec2(680.f, 28.f));

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Wordlist id:");
    ImGui::SameLine();
    aida::ui::input_text("##cd_wl", st.disc_wordlist_id, sizeof(st.disc_wordlist_id), "dirs/common-100", false, ImVec2(260.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Extensions:");
    ImGui::SameLine();
    aida::ui::input_text("##cd_ext", st.disc_extensions, sizeof(st.disc_extensions), ".php,.bak,.zip", false, ImVec2(260.f, 28.f));

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Match status:");
    ImGui::SameLine();
    aida::ui::input_text("##cd_ms", st.disc_match_status, sizeof(st.disc_match_status), "200,301", false, ImVec2(220.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Filter status:");
    ImGui::SameLine();
    aida::ui::input_text("##cd_fs", st.disc_filter_status, sizeof(st.disc_filter_status), "404", false, ImVec2(220.f, 28.f));

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Concurrency:");
    ImGui::SameLine();
    aida::ui::input_int("##cd_conc", &st.disc_concurrency, ImVec2(80.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Delay ms:");
    ImGui::SameLine();
    aida::ui::input_int("##cd_delay", &st.disc_delay_ms, ImVec2(80.f, 28.f));
    ImGui::SameLine();
    aida::ui::toggle_switch("##cd_rec", &st.disc_recurse);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Recurse");
    ImGui::SameLine();
    aida::ui::input_int("##cd_rdepth", &st.disc_recurse_depth, ImVec2(60.f, 28.f));
    ImGui::SameLine();
    aida::ui::toggle_switch("##cd_calib", &st.disc_auto_calibrate);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Auto-calibrate");
    ImGui::SameLine();
    aida::ui::toggle_switch("##cd_fr", &st.disc_follow_redir);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Follow redir");

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Cookie:");
    aida::ui::input_text("##cd_cook", st.disc_cookie, sizeof(st.disc_cookie), "session=...", false, ImVec2(680.f, 28.f));
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "User-Agent:");
    aida::ui::input_text("##cd_ua", st.disc_user_agent, sizeof(st.disc_user_agent), "AiDA-ContentDiscovery/1.0", false, ImVec2(420.f, 28.f));

    ImGui::Spacing();
    const bool operation_pending = st.operation.pending();
    ImGui::BeginDisabled(operation_pending);
    if (aida::ui::button("Start", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm))
    {
        content_discovery::config_t cfg;
        cfg.target_url = st.disc_target;
        cfg.wordlist_id = st.disc_wordlist_id;
        cfg.extensions = split_csv(st.disc_extensions);
        cfg.concurrency = std::max(1, st.disc_concurrency);
        cfg.delay_ms = std::max(0, st.disc_delay_ms);
        cfg.match_status = split_csv_ints(st.disc_match_status);
        cfg.filter_status = split_csv_ints(st.disc_filter_status);
        cfg.recurse = st.disc_recurse;
        cfg.recurse_depth = std::max(1, st.disc_recurse_depth);
        cfg.auto_calibrate = st.disc_auto_calibrate;
        cfg.follow_redirects = st.disc_follow_redir;
        cfg.cookie_header = st.disc_cookie;
        cfg.user_agent = st.disc_user_agent;
        submit_recon_operation("network.recon.discovery.start", "Start content discovery", st.disc_target,
            [cfg = std::move(cfg)]() {
            aida::burp::ui_operation::result_t result;
            const std::uint64_t id = content_discovery::start(cfg);
            result.success = id != 0;
            result.message = result.success ? "Content discovery started." : content_discovery::last_error();
            if (id != 0) {
                ui().started_run_domain.store(2, std::memory_order_release);
                ui().started_run_id.store(id, std::memory_order_release);
            }
            return result;
        });
    }
    ImGui::SameLine();
    if (aida::ui::button("Stop Selected", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm))
    {
        if (st.disc_selected != 0) {
            const auto runs = std::atomic_load_explicit(&st.discovery_runs, std::memory_order_acquire);
            if (const auto* run = find_run(*runs, st.disc_selected))
                submit_stop(2, run->id, run->started_unix_ms);
        }
    }
    ImGui::SameLine();
    if (aida::ui::button("Remove Selected", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
    {
        if (st.disc_selected != 0) {
            const auto runs = std::atomic_load_explicit(&st.discovery_runs, std::memory_order_acquire);
            if (const auto* run = find_run(*runs, st.disc_selected))
                request_remove_review(2, run->id, run->started_unix_ms);
        }
    }
    ImGui::EndDisabled();

    ImGui::Spacing();
    const auto runs = std::atomic_load_explicit(&st.discovery_runs,
        std::memory_order_acquire);
    if (ImGui::BeginTable("##cd_tbl", 7,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp,
        ImVec2(0.f, 200.f)))
    {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Phase");
        ImGui::TableSetupColumn("Attempts");
        ImGui::TableSetupColumn("Total");
        ImGui::TableSetupColumn("Hits");
        ImGui::TableSetupColumn("Errors");
        ImGui::TableSetupColumn("Filtered");
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(runs->size()));
        while (clipper.Step())
        for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index)
        {
            const auto& d = (*runs)[static_cast<std::size_t>(index)];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char buf[32]; snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(d.id));
            bool sel = (d.id == st.disc_selected);
            if (ImGui::Selectable(buf, sel, ImGuiSelectableFlags_SpanAllColumns)) st.disc_selected = d.id;
            ImGui::TableNextColumn(); ImGui::TextUnformatted(disc_phase_label(d.phase));
            ImGui::TableNextColumn(); ImGui::Text("%d", d.attempts);
            ImGui::TableNextColumn(); ImGui::Text("%d", d.total);
            ImGui::TableNextColumn(); ImGui::Text("%d", d.hits);
            ImGui::TableNextColumn(); ImGui::Text("%d", d.errors);
            ImGui::TableNextColumn(); ImGui::Text("%d", d.filtered);
        }
        ImGui::EndTable();
    }

    if (st.disc_selected != 0)
    {
        const auto* ds = find_run(*runs, st.disc_selected);
        if (ds) {
        ImGui::Spacing();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
            "Hits (%zu) | Calibrated size range: %zu-%zu", ds->hits_list.size(), ds->calibrated_size_lo, ds->calibrated_size_hi);
        if (ImGui::BeginTable("##cd_hits", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
            ImVec2(0.f, 220.f)))
        {
            ImGui::TableSetupColumn("Status");
            ImGui::TableSetupColumn("Bytes");
            ImGui::TableSetupColumn("Latency");
            ImGui::TableSetupColumn("Payload");
            ImGui::TableSetupColumn("URL", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(ds->hits_list.size()));
            while (clipper.Step())
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index)
            {
                const auto& h = ds->hits_list[static_cast<std::size_t>(index)];
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::Text("%d", h.status);
                ImGui::TableNextColumn(); ImGui::Text("%zu", h.body_bytes);
                ImGui::TableNextColumn(); ImGui::Text("%llu", static_cast<unsigned long long>(h.latency_ms));
                ImGui::TableNextColumn(); ImGui::TextUnformatted(h.payload.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(h.url.c_str());
            }
            ImGui::EndTable();
        }
        }
    }
}

void render_subdomains(ui_state_t& st, float alpha)
{
    const auto& th = aida::ui::resolved();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Subdomain Enumeration");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Domain:");
    ImGui::SameLine();
    aida::ui::input_text("##sub_dom", st.sub_domain, sizeof(st.sub_domain), "example.com", false, ImVec2(280.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Brute wordlist:");
    ImGui::SameLine();
    aida::ui::input_text("##sub_wl", st.sub_wordlist_id, sizeof(st.sub_wordlist_id), "subdomains/top1000", false, ImVec2(240.f, 28.f));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Concurrency:");
    ImGui::SameLine();
    aida::ui::input_int("##sub_conc", &st.sub_concurrency, ImVec2(80.f, 28.f));

    ImGui::Spacing();
    aida::ui::toggle_switch("##sub_passive", &st.sub_run_passive);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Passive");
    ImGui::SameLine();
    aida::ui::toggle_switch("##sub_brute", &st.sub_run_brute);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Brute");
    ImGui::SameLine();
    aida::ui::toggle_switch("##sub_crt", &st.sub_passive_crtsh);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "crt.sh");
    ImGui::SameLine();
    aida::ui::toggle_switch("##sub_buf", &st.sub_passive_bufferover);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "bufferover");
    ImGui::SameLine();
    aida::ui::toggle_switch("##sub_ht", &st.sub_passive_hackertarget);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "hackertarget");

    ImGui::Spacing();
    const bool operation_pending = st.operation.pending();
    ImGui::BeginDisabled(operation_pending);
    if (aida::ui::button("Start Enum", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm))
    {
        subdomain_enum::config_t cfg;
        cfg.domain = st.sub_domain;
        cfg.brute_wordlist_id = st.sub_wordlist_id;
        cfg.run_passive = st.sub_run_passive;
        cfg.run_brute = st.sub_run_brute;
        cfg.resolver_concurrency = std::max(1, st.sub_concurrency);
        if (st.sub_passive_crtsh) cfg.passive_sources.push_back("crt.sh");
        if (st.sub_passive_bufferover) cfg.passive_sources.push_back("bufferover");
        if (st.sub_passive_hackertarget) cfg.passive_sources.push_back("hackertarget");
        submit_recon_operation("network.recon.subdomain.start", "Start subdomain enumeration", st.sub_domain,
            [cfg = std::move(cfg)]() {
            aida::burp::ui_operation::result_t result;
            const std::uint64_t id = subdomain_enum::start(cfg);
            result.success = id != 0;
            result.message = result.success ? "Subdomain enumeration started." : subdomain_enum::last_error();
            if (id != 0) {
                ui().started_run_domain.store(3, std::memory_order_release);
                ui().started_run_id.store(id, std::memory_order_release);
            }
            return result;
        });
    }
    ImGui::SameLine();
    if (aida::ui::button("Stop Selected", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm))
    {
        if (st.sub_selected != 0) {
            const auto runs = std::atomic_load_explicit(&st.subdomain_runs, std::memory_order_acquire);
            if (const auto* run = find_run(*runs, st.sub_selected))
                submit_stop(3, run->id, run->started_unix_ms);
        }
    }
    ImGui::SameLine();
    if (aida::ui::button("Remove Selected", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
    {
        if (st.sub_selected != 0) {
            const auto runs = std::atomic_load_explicit(&st.subdomain_runs, std::memory_order_acquire);
            if (const auto* run = find_run(*runs, st.sub_selected))
                request_remove_review(3, run->id, run->started_unix_ms);
        }
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    const bool export_pending = st.sub_export_pending.load(std::memory_order_acquire);
    const bool export_available = st.sub_selected != 0 && !export_pending;
    ImGui::BeginDisabled(!export_available);
    if (aida::ui::button(export_pending ? "Exporting..." : "Export CSV",
        aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
    {
        const uint64_t run_id = st.sub_selected;
        ::diag::log_tagged_fmt("recon_v", "sub_enum_export_csv id=%llu",
            static_cast<unsigned long long>(run_id));
        if (!queue_subdomain_export(run_id))
            toast_notification::push("The CSV export could not be queued; see Task Center",
                toast_notification::toast_type_t::error);
    }
    ImGui::EndDisabled();
    if (!export_available && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("%s", export_pending ? "A subdomain CSV export is already running" :
            "Select a subdomain enumeration run first");

    ImGui::Spacing();
    const auto runs = std::atomic_load_explicit(&st.subdomain_runs,
        std::memory_order_acquire);
    if (ImGui::BeginTable("##sub_tbl", 5,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp,
        ImVec2(0.f, 160.f)))
    {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Phase");
        ImGui::TableSetupColumn("Passive");
        ImGui::TableSetupColumn("Brute Tried");
        ImGui::TableSetupColumn("Brute Hit");
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(runs->size()));
        while (clipper.Step())
        for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index)
        {
            const auto& e = (*runs)[static_cast<std::size_t>(index)];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char buf[32]; snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(e.id));
            bool sel = (e.id == st.sub_selected);
            if (ImGui::Selectable(buf, sel, ImGuiSelectableFlags_SpanAllColumns)) st.sub_selected = e.id;
            ImGui::TableNextColumn(); ImGui::TextUnformatted(sub_phase_label(e.phase));
            ImGui::TableNextColumn(); ImGui::Text("%d", e.passive_count);
            ImGui::TableNextColumn(); ImGui::Text("%d", e.brute_attempts);
            ImGui::TableNextColumn(); ImGui::Text("%d", e.brute_resolved);
        }
        ImGui::EndTable();
    }

    if (st.sub_selected != 0)
    {
        const auto* es = find_run(*runs, st.sub_selected);
        if (es) {
        ImGui::Spacing();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
            "Subdomains (%zu)", es->results.size());
        if (ImGui::BeginTable("##sub_res", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
            ImVec2(0.f, 240.f)))
        {
            ImGui::TableSetupColumn("FQDN", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Resolves");
            ImGui::TableSetupColumn("IPs");
            ImGui::TableSetupColumn("Sources");
            ImGui::TableHeadersRow();
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(es->results.size()));
            while (clipper.Step())
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index)
            {
                const auto& s = es->results[static_cast<std::size_t>(index)];
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(s.fqdn.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(s.resolves ? "yes" : "no");
                ImGui::TableNextColumn();
                std::string ips;
                for (size_t i = 0; i < s.ips.size(); ++i) { if (i) ips += ", "; ips += s.ips[i]; }
                ImGui::TextUnformatted(ips.c_str());
                ImGui::TableNextColumn();
                std::string srcs;
                for (size_t i = 0; i < s.sources.size(); ++i) { if (i) srcs += ", "; srcs += s.sources[i]; }
                ImGui::TextUnformatted(srcs.c_str());
            }
            ImGui::EndTable();
        }
        }
    }
}

void render_payloads(ui_state_t& st, float alpha)
{
    const auto& th = aida::ui::resolved();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Payload Library");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Filter:");
    ImGui::SameLine();
    aida::ui::input_text("##pl_filter", st.pl_filter, sizeof(st.pl_filter), "substring", false, ImVec2(220.f, 28.f));

    const auto sets = std::atomic_load_explicit(&st.payload_sets, std::memory_order_acquire);
    std::string filter_lo = st.pl_filter;
    std::transform(filter_lo.begin(), filter_lo.end(), filter_lo.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

    ImGui::Spacing();
    ImGui::Columns(2, "##pl_cols", true);
    ImGui::SetColumnWidth(0, 360.f);
    ImGui::BeginChild("##pl_list", ImVec2(0.f, 480.f), true);
    for (const auto& s : *sets)
    {
        if (!filter_lo.empty())
        {
            std::string idlo = s.id;
            std::transform(idlo.begin(), idlo.end(), idlo.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (idlo.find(filter_lo) == std::string::npos) continue;
        }
        bool sel = (std::strcmp(s.id.c_str(), st.pl_selected_id) == 0);
        ImGui::PushID(s.id.c_str());
        char title[256];
        snprintf(title, sizeof(title), "%s%s", s.id.c_str(), s.builtin ? "  [builtin]" : "  [custom]");
        if (ImGui::Selectable(title, sel))
        {
            std::strncpy(st.pl_selected_id, s.id.c_str(), sizeof(st.pl_selected_id) - 1);
            st.pl_selected_id[sizeof(st.pl_selected_id) - 1] = '\0';
        }
        ImGui::PopID();
    }
    ImGui::EndChild();

    ImGui::NextColumn();
    ImGui::BeginChild("##pl_detail", ImVec2(0.f, 480.f), true);

    if (st.pl_selected_id[0] != '\0')
    {
        const auto found = std::find_if(sets->begin(), sets->end(), [&st](const auto& set) {
            return set.id == st.pl_selected_id;
        });
        const auto* p = found == sets->end() ? nullptr : &*found;
        if (p)
        {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "%s", p->label.c_str());
            ImGui::TextWrapped("%s", p->description.c_str());
            ImGui::Text("Entries: %zu", p->entries.size());
            ImGui::Spacing();
            ImGui::BeginChild("##pl_entries", ImVec2(0.f, 320.f), true);
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(p->entries.size()));
            while (clipper.Step())
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index)
                ImGui::TextUnformatted(p->entries[static_cast<std::size_t>(index)].c_str());
            ImGui::EndChild();
            if (!p->builtin)
            {
                if (aida::ui::button("Delete Set", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm))
                {
                    st.reviewed_payload_id = p->id;
                    st.reviewed_payload_builtin = p->builtin;
                    ImGui::OpenPopup("Review payload set removal");
                }
            }
        }
    }
    else
    {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "(select a set on the left)");
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Add custom set:");
    aida::ui::input_text("##pl_new_id", st.pl_new_id, sizeof(st.pl_new_id), "id e.g. custom/xss-fast", false, ImVec2(280.f, 28.f));
    aida::ui::input_text("##pl_new_label", st.pl_new_label, sizeof(st.pl_new_label), "label", false, ImVec2(280.f, 28.f));
    aida::ui::input_text("##pl_new_desc", st.pl_new_desc, sizeof(st.pl_new_desc), "description", false, ImVec2(420.f, 28.f));
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Entries (one per line):");
    ImGui::InputTextMultiline("##pl_new_entries", st.pl_new_entries, sizeof(st.pl_new_entries), ImVec2(0.f, 96.f));
    ImGui::BeginDisabled(st.operation.pending());
    if (aida::ui::button("Add", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm))
    {
        std::vector<std::string> entries;
        std::string cur;
        for (const char* p2 = st.pl_new_entries; *p2; ++p2)
        {
            if (*p2 == '\n') { if (!cur.empty()) entries.push_back(cur); cur.clear(); }
            else if (*p2 != '\r') cur.push_back(*p2);
        }
        if (!cur.empty()) entries.push_back(cur);
        st.clear_payload_inputs_after_success = submit_payload_add(
            st.pl_new_id, st.pl_new_label, st.pl_new_desc, std::move(entries));
    }
    ImGui::EndDisabled();

    ImGui::EndChild();
    ImGui::Columns(1);
}

}

bool initialize()
{
    auto& s = ui();
    bool expected = false;
    if (!s.initialized.compare_exchange_strong(expected, true)) return true;
    ::diag::log_tagged("recon_v", "initialize");
    const bool payloads_ready = payloads::initialize();
    const bool crawler_ready = crawler::initialize();
    const bool discovery_ready = content_discovery::initialize();
    const bool subdomain_ready = subdomain_enum::initialize();
    const bool ready = payloads_ready && crawler_ready && discovery_ready && subdomain_ready;
    if (!ready)
        s.initialized.store(false, std::memory_order_release);
    return ready;
}

void shutdown()
{
    auto& s = ui();
    if (!s.initialized.exchange(false)) return;
    ::diag::log_tagged("recon_v", "shutdown");
    crawler::shutdown();
    content_discovery::shutdown();
    subdomain_enum::shutdown();
    payloads::shutdown();
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    auto& s = ui();
    if (!s.initialization_attempted) {
        s.initialization_attempted = true;
        submit_initialization();
    }

    const auto completion = s.operation.completion();
    if (completion && completion->generation > s.observed_operation_generation) {
        s.observed_operation_generation = completion->generation;
        s.initialization_requested.store(false, std::memory_order_release);
        const int started_domain = s.started_run_domain.exchange(0, std::memory_order_acq_rel);
        const std::uint64_t started_id = s.started_run_id.exchange(0, std::memory_order_acq_rel);
        if (started_id != 0) {
            if (started_domain == 1) s.crawler_selected = started_id;
            else if (started_domain == 2) s.disc_selected = started_id;
            else if (started_domain == 3) s.sub_selected = started_id;
        }
        if (s.clear_payload_inputs_after_success) {
            if (completion->result.success) {
                s.pl_new_id[0] = '\0';
                s.pl_new_label[0] = '\0';
                s.pl_new_desc[0] = '\0';
                s.pl_new_entries[0] = '\0';
            }
            s.clear_payload_inputs_after_success = false;
        }
        if (s.awaiting_remove_completion) {
            if (completion->result.success) {
                if (s.review_domain == 1 && s.crawler_selected == s.reviewed_id) s.crawler_selected = 0;
                else if (s.review_domain == 2 && s.disc_selected == s.reviewed_id) s.disc_selected = 0;
                else if (s.review_domain == 3 && s.sub_selected == s.reviewed_id) s.sub_selected = 0;
            }
            s.awaiting_remove_completion = false;
        }
        if (s.awaiting_payload_remove_completion) {
            if (completion->result.success && s.reviewed_payload_id == s.pl_selected_id)
                s.pl_selected_id[0] = '\0';
            s.awaiting_payload_remove_completion = false;
            s.reviewed_payload_id.clear();
        }
        request_run_refresh();
    }

    const std::uint64_t now_ms = aida::infra::executor::now_ms();
    if (s.initialized.load(std::memory_order_acquire) &&
        now_ms - s.last_refresh_ms >= 200) {
        s.last_refresh_ms = now_ms;
        request_run_refresh();
    }

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##recon_view", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    if (!s.initialized.load(std::memory_order_acquire)) {
        if (s.operation.pending()) {
            ImGui::TextUnformatted("Loading Recon state...");
        } else {
            ImGui::TextUnformatted(completion ? completion->result.message.c_str() : "Recon initialization is unavailable.");
            if (aida::ui::button("Retry", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
                submit_initialization();
        }
        ImGui::EndChild();
        return;
    }

    if (completion) {
        const auto color = completion->result.success ? aida::ui::resolved().success : aida::ui::resolved().error;
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(color, alpha)),
            "%s", completion->result.message.c_str());
        if (!completion->result.success && !s.operation.pending()) {
            ImGui::SameLine();
            if (aida::ui::button("Retry operation", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
                static_cast<void>(s.operation.retry());
        }
    }

    if (aida::ui::design::begin_dialog_exact("Review Recon removal",
        ImVec2(520.f, 280.f), ImVec2(400.f, 230.f))) {
        const float footer = aida::ui::design::dialog_footer_reserve_height("Remove");
        if (aida::ui::design::begin_dialog_body("recon_removal_review_body", footer)) {
            ImGui::Text("Remove Recon run %llu?", static_cast<unsigned long long>(s.reviewed_id));
            ImGui::TextWrapped("The selected run and its retained results will be removed after exact identity revalidation.");
        }
        aida::ui::design::end_dialog_body();
        const auto result = aida::ui::design::dialog_footer(
            "recon_removal_review_footer", "Remove",
            s.reviewed_id != 0 && !s.operation.pending(), true);
        if (result.confirmed) {
            s.awaiting_remove_completion = submit_reviewed_remove(
                s.review_domain, s.reviewed_id, s.reviewed_started_ms);
            ImGui::CloseCurrentPopup();
        }
        if (result.cancelled)
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    if (aida::ui::design::begin_dialog_exact("Review payload set removal",
        ImVec2(520.f, 280.f), ImVec2(400.f, 230.f))) {
        const float footer = aida::ui::design::dialog_footer_reserve_height("Remove set");
        if (aida::ui::design::begin_dialog_body("payload_set_removal_review_body", footer)) {
            ImGui::Text("Remove payload set '%s'?", s.reviewed_payload_id.c_str());
            ImGui::TextWrapped("The custom payload set and its persisted file will be removed after exact identity revalidation.");
        }
        aida::ui::design::end_dialog_body();
        const auto result = aida::ui::design::dialog_footer(
            "payload_set_removal_review_footer", "Remove set",
            !s.reviewed_payload_id.empty() && !s.operation.pending(), true);
        if (result.confirmed) {
            s.awaiting_payload_remove_completion = submit_payload_remove(
                s.reviewed_payload_id, s.reviewed_payload_builtin);
            ImGui::CloseCurrentPopup();
        }
        if (result.cancelled) {
            s.reviewed_payload_id.clear();
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    const char* labels[] = { "Crawler", "Content Discovery", "Subdomains", "Payload Library" };
    for (int i = 0; i < 4; ++i)
    {
        bool is_active = (s.active_tab == i);
        if (i > 0) ImGui::SameLine();
        const aida::ui::button_kind_t k = is_active ? aida::ui::button_kind_t::primary : aida::ui::button_kind_t::secondary;
        if (aida::ui::button(labels[i], k, aida::ui::size_t_::sm)) {
            ::diag::log_tagged_fmt("recon_v", "tab_switch tab=%s", labels[i]);
            s.active_tab = i;
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    switch (static_cast<tab_t>(s.active_tab))
    {
        case tab_t::crawler:           render_crawler(s, alpha); break;
        case tab_t::content_discovery: render_content_discovery(s, alpha); break;
        case tab_t::subdomains:        render_subdomains(s, alpha); break;
        case tab_t::payloads:          render_payloads(s, alpha); break;
    }

    ImGui::EndChild();
}

}
}
}
