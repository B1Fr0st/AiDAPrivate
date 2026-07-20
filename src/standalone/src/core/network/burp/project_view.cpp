#include "project_view.hpp"
#include "../../ui/task_center.hpp"
#include "imgui/imgui.h"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../../preview/network_preview_adapter.hpp"
#else
#include "project.hpp"
#include "../../infra/executor.hpp"
#include "../../infra/ui_thread_dispatcher.hpp"
#endif
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <exception>
#include <string>
#include <utility>

namespace aida::burp::project_view {
namespace {
struct state_t {
    char path[1024] = "aida-burp-project.json";
    bool replace_existing = true;
    std::atomic<bool> running{false};
    std::atomic<bool> dispatch_failed{false};
    std::string status;
    bool succeeded = false;
};
state_t& state() { static state_t value; return value; }
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
void start_operation(bool save) {
    auto& current = state();
    if (current.running.exchange(true, std::memory_order_acq_rel)) return;
    const std::string path = current.path;
    const bool replace_existing = current.replace_existing;
    current.status = save ? "Saving project..." : "Loading project...";
    current.succeeded = false;
    static std::atomic<std::uint64_t> operation_sequence{1};
    const std::string task_id = "network.project." + std::to_string(
        operation_sequence.fetch_add(1, std::memory_order_acq_rel));
    aida::ui::task_center::task_registration_t registration;
    registration.id = task_id;
    registration.source = "network.project";
    registration.owner = "network.project";
    registration.owner_view = "view.network.project";
    registration.owner_action = save ? "save" : "load";
    registration.target = path;
    registration.label = save ? "Save Burp project" : "Load Burp project";
    registration.stage = save ? "Serializing project" : "Restoring project";
    if (!aida::ui::task_center::register_task(std::move(registration))) {
        current.status = "Task Center rejected the project operation";
        current.running.store(false, std::memory_order_release);
        return;
    }
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "network.project";
    submission.label = save ? "network.project.save" : "network.project.load";
    submission.thread_class = "blocking_file_io";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 4;
    submission.ui_access_policy = "immutable_snapshots_only";
    submission.failure_policy = "typed_diagnostic";
    submission.body = [save, path, replace_existing, task_id] {
        bool ok = false;
        std::string detail;
        try {
            ok = save ? project::save_to_file(path)
                      : project::load_from_file(path, replace_existing);
            detail = ok ? (save ? "Project saved" : "Project loaded") : project::last_error();
        } catch (const std::exception& exception) {
            detail = exception.what();
        } catch (...) {
            detail = "Project operation failed with an unknown exception";
        }
        const bool posted = aida::ui_thread::post([ok, detail = std::move(detail), task_id]() mutable {
            auto& current = state();
            current.succeeded = ok;
            current.status = detail.empty() ? "Project operation failed" : std::move(detail);
            current.running.store(false, std::memory_order_release);
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                ok ? aida::ui::task_center::task_state_t::completed
                   : aida::ui::task_center::task_state_t::failed,
                1.0f, ok ? "Completed" : "Failed", current.status,
                ok ? std::string{} : "network.project.operation.failure." + task_id));
        }, "network_project", "operation_result", "worker_result");
        if (!posted) {
            state().dispatch_failed.store(true, std::memory_order_release);
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                aida::ui::task_center::task_state_t::failed, 1.0f,
                "UI publication failed", "Project result could not reach the UI thread",
                "network.project.dispatch.failure." + task_id));
        }
    };
    const auto submitted = aida::infra::executor::submit(std::move(submission));
    if (!submitted.submitted) {
        current.status = "Project operation could not be scheduled: " + submitted.reject_reason;
        current.running.store(false, std::memory_order_release);
        static_cast<void>(aida::ui::task_center::update_task(task_id,
            aida::ui::task_center::task_state_t::failed, 1.0f,
            "Scheduling failed", current.status,
            "network.project.schedule.failure." + task_id));
        return;
    }
    static_cast<void>(aida::ui::task_center::update_task(task_id,
        aida::ui::task_center::task_state_t::running, -1.0f,
        save ? "Serializing project" : "Restoring project"));
}
#endif
}

void render() {
    auto& current = state();
    if (current.dispatch_failed.exchange(false, std::memory_order_acq_rel)) {
        current.succeeded = false;
        current.status = "Project result could not reach the UI thread";
        current.running.store(false, std::memory_order_release);
    }
    ImGui::TextUnformatted("Burp Project");
    ImGui::Separator();
    ImGui::SetNextItemWidth((std::max)(220.f, ImGui::GetContentRegionAvail().x - 12.f));
    ImGui::InputTextWithHint("##network_project_path", "Project file path", current.path, sizeof(current.path));
    ImGui::Checkbox("Replace existing state when loading", &current.replace_existing);
    ImGui::BeginDisabled(current.running.load(std::memory_order_acquire) || current.path[0] == '\0');
    if (ImGui::Button("Save Project")) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        current.succeeded = true;
        current.status = "Studio parity receipt: project save accepted without filesystem access";
        aida::preview::network::record_receipt("Burp project save", current.path);
#else
        start_operation(true);
#endif
    }
    ImGui::SameLine();
    if (ImGui::Button("Load Project")) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        current.succeeded = true;
        current.status = current.replace_existing
            ? "Studio parity receipt: replace-load accepted without filesystem access"
            : "Studio parity receipt: merge-load accepted without filesystem access";
        aida::preview::network::record_receipt("Burp project load", current.path);
#else
        start_operation(false);
#endif
    }
    ImGui::EndDisabled();
    if (!current.status.empty()) {
        ImGui::Spacing();
        const ImVec4 color = current.succeeded ? ImVec4(0.35f, 0.82f, 0.55f, 1.f)
                                               : ImVec4(0.95f, 0.55f, 0.32f, 1.f);
        ImGui::PushStyleColor(ImGuiCol_Text, color);
        ImGui::TextWrapped("%s", current.status.c_str());
        ImGui::PopStyleColor();
    }
}
}
