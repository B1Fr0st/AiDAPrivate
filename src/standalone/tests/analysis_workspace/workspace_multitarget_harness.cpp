#include "workspace_fixture_builder.hpp"

#include "../../src/core/analysis/workspace/patched_export.hpp"

#include <future>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace {

using namespace aida::analysis;
using namespace aida::analysis::test_fixture;

class operation_overlap_gate_t final {
public:
    explicit operation_overlap_gate_t(std::size_t expected) : expected_(expected) {}

    void enter()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        ++entered_;
        ++active_;
        peak_active_ = (std::max)(peak_active_, active_);
        wake_.notify_all();
        if (!wake_.wait_for(lock, std::chrono::seconds(5), [&] { return released_; })) {
            --active_;
            throw fixture_error_t("multi-workspace operation start gate timed out");
        }
    }

    void leave()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (active_ != 0)
            --active_;
        wake_.notify_all();
    }

    bool release_when_ready()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        const bool ready = wake_.wait_for(lock, std::chrono::seconds(5), [&] {
            return entered_ == expected_;
        });
        released_ = true;
        wake_.notify_all();
        return ready;
    }

    std::size_t peak_active() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return peak_active_;
    }

private:
    const std::size_t expected_;
    mutable std::mutex mutex_;
    std::condition_variable wake_;
    std::size_t entered_ = 0;
    std::size_t active_ = 0;
    std::size_t peak_active_ = 0;
    bool released_ = false;
};

class operation_overlap_scope_t final {
public:
    explicit operation_overlap_scope_t(operation_overlap_gate_t& gate) : gate_(gate)
    {
        gate_.enter();
        active_ = true;
    }
    ~operation_overlap_scope_t()
    {
        if (active_)
            gate_.leave();
    }
    operation_overlap_scope_t(const operation_overlap_scope_t&) = delete;
    operation_overlap_scope_t& operator=(const operation_overlap_scope_t&) = delete;
private:
    operation_overlap_gate_t& gate_;
    bool active_ = false;
};

address_t address_at(const std::shared_ptr<analysis_workspace_t>& workspace,
                     std::uint64_t rva)
{
    address_t value;
    value.space = address_space_id_t::virtual_address;
    value.value = workspace->image()->image_base() + rva;
    value.architecture = workspace->identity().architecture();
    value.mode = workspace->image()->architecture_mode();
    return value;
}

struct workspace_probe_t {
    binary_id_t binary_id;
    sha256_digest_t content_hash;
    sha256_digest_t pseudocode_hash;
    std::string marker;
    std::uint64_t overlay_revision = 0;
    std::uint64_t analysis_revision = 0;
    entity_id_t function_id = 0;
    std::size_t history_size = 0;
    std::size_t cache_entries = 0;
    std::uint64_t selection = 0;
};

workspace_probe_t exercise_workspace(const std::shared_ptr<analysis_workspace_t>& workspace,
                                     std::size_t index,
                                     bool mutate = true)
{
    const auto snapshot = workspace->snapshot();
    const auto search = workspace->search_index();
    const auto decompiler = workspace->decompiler();
    const auto overlay = workspace->overlay();
    if (!snapshot || snapshot->instructions.empty() || snapshot->functions.empty() ||
        !search || !decompiler || !overlay)
        throw fixture_error_t("workspace probe services are incomplete");

    const std::string marker = "AiDA workspace fixture " + std::to_string(20 + index);
    auto searched = search->find_text(marker, 0, 32, workspace->cancellation_token());
    if (!searched || searched.value().hits.empty())
        throw fixture_error_t("workspace-local marker search returned no result");
    for (const auto& hit : searched.value().hits) {
        if (hit.text.find(marker) == std::string::npos)
            throw fixture_error_t("search result crossed workspace marker identity");
    }

    auto first = decompiler->decompile(snapshot->functions.front().start, {},
                                       workspace->cancellation_token());
    if (!first || first.value().binary_id != workspace->identity().binary_id() ||
        first.value().function_id != snapshot->functions.front().id ||
        first.value().pseudocode.find_first_not_of(" \t\r\n") == std::string::npos ||
        first.value().line_to_address.empty())
        throw fixture_error_t("workspace-local decompilation did not return mapped pseudocode");
    auto cached = decompiler->decompile(snapshot->functions.front().start, {},
                                        workspace->cancellation_token());
    if (!cached || !cached.value().cache_hit ||
        cached.value().pseudocode != first.value().pseudocode)
        throw fixture_error_t("workspace-local decompiler cache did not return the same function");
    auto pseudocode_hash = sha256_text(first.value().pseudocode);
    if (!pseudocode_hash)
        throw fixture_error_t(pseudocode_hash.error().message);

    if (mutate) {
        overlay_transaction_request_t mutation;
        mutation.expected_revision = workspace->overlay_revision();
        mutation.idempotency_key = workspace->identity().binary_id().to_hex() + "-multitarget";
        overlay_operation_t comment;
        comment.kind = overlay_operation_kind_t::comment;
        comment.address = address_at(workspace, 0x1000);
        comment.text = "comment-" + std::to_string(index);
        mutation.operations.push_back(comment);
        overlay_operation_t name = comment;
        name.kind = overlay_operation_kind_t::name;
        name.text.clear();
        name.name = "function_" + std::to_string(index);
        mutation.operations.push_back(name);
        overlay_operation_t type = comment;
        type.kind = overlay_operation_kind_t::type_application;
        type.text.clear();
        type.variable = "global_" + std::to_string(index);
        type.name = type.variable;
        type.type = "unsigned int";
        type.address = address_at(workspace, 0x1040);
        mutation.operations.push_back(type);
        overlay_operation_t patch = comment;
        patch.kind = overlay_operation_kind_t::byte_patch;
        patch.text.clear();
        patch.address = address_at(workspace, 0x1010);
        patch.bytes = {static_cast<std::uint8_t>(0xA0 + index)};
        mutation.operations.push_back(patch);
        overlay_operation_t asm_patch = comment;
        asm_patch.kind = overlay_operation_kind_t::assembly_patch;
        asm_patch.text.clear();
        asm_patch.address = address_at(workspace, 0x1020);
        asm_patch.bytes = {0x90};
        asm_patch.assembly = "nop";
        mutation.operations.push_back(asm_patch);
        overlay_operation_t int_patch = comment;
        int_patch.kind = overlay_operation_kind_t::integer_patch;
        int_patch.text.clear();
        int_patch.address = address_at(workspace, 0x1030);
        int_patch.bytes = {static_cast<std::uint8_t>(0x10 + index), 0x00};
        int_patch.integer_type = "u16le";
        int_patch.integer_value = std::to_string(0x10 + index);
        mutation.operations.push_back(int_patch);
        auto committed = overlay->transact(mutation, workspace->cancellation_token());
        if (!committed || !committed.value().committed ||
            committed.value().operations.size() != mutation.operations.size())
            throw fixture_error_t("workspace-local overlay family commit failed");
    }

    const auto selection = address_at(workspace, 0x1000 + index);
    auto view_update = workspace->update_view_state([&](workspace_view_state_t& state) {
        state.selection = selection;
        state.navigation_back = {address_at(workspace, 0x1000), selection};
        state.navigation_forward = {address_at(workspace, 0x1005 + index)};
        state.bookmarks = {selection};
    });
    if (!view_update)
        throw fixture_error_t(view_update.error().message);
    const auto view = workspace->view_state();
    const auto overlay_snapshot = overlay->snapshot();
    const auto decompiler_snapshot = decompiler->snapshot();
    const auto history = decompiler->history();
    if (!view.selection || *view.selection != selection || view.navigation_back.size() != 2 ||
        view.navigation_forward.size() != 1 || view.bookmarks.size() != 1 ||
        overlay_snapshot.items.size() != 6 || decompiler_snapshot.memory_cache_entries == 0 ||
        history.empty() || history.back().function_id != snapshot->functions.front().id)
        throw fixture_error_t("workspace-local overlay/cache/history/view state was not published");

    workspace_probe_t result;
    result.binary_id = workspace->identity().binary_id();
    result.content_hash = workspace->identity().content_hash();
    result.pseudocode_hash = pseudocode_hash.value();
    result.marker = marker;
    result.overlay_revision = workspace->overlay_revision();
    result.analysis_revision = workspace->analysis_revision();
    result.function_id = first.value().function_id;
    result.history_size = history.size();
    result.cache_entries = decompiler_snapshot.memory_cache_entries;
    result.selection = view.selection->value;
    return result;
}

void verify_undo_redo_across_workspaces(
    const std::vector<std::shared_ptr<analysis_workspace_t>>& workspaces)
{
    for (std::size_t index = 0; index < workspaces.size(); ++index) {
        const auto revision_before = workspaces[index]->overlay_revision();
        auto undone = workspaces[index]->overlay()->undo(workspaces[index]->overlay_revision());
        if (!undone || !undone.value().committed ||
            workspaces[index]->overlay_revision() != revision_before - 1)
            throw fixture_error_t("multi-workspace undo did not decrement revision");
        const auto snapshot_after_undo = workspaces[index]->overlay()->snapshot();
        if (!snapshot_after_undo.items.empty())
            throw fixture_error_t("multi-workspace undo did not clear overlay items");
        auto redone = workspaces[index]->overlay()->redo(workspaces[index]->overlay_revision());
        if (!redone || !redone.value().committed ||
            workspaces[index]->overlay_revision() != revision_before)
            throw fixture_error_t("multi-workspace redo did not restore revision");
        const auto snapshot_after_redo = workspaces[index]->overlay()->snapshot();
        if (snapshot_after_redo.items.size() != 6)
            throw fixture_error_t("multi-workspace redo did not restore all overlay items");
    }
}

void verify_export_across_workspaces(
    const std::vector<std::shared_ptr<analysis_workspace_t>>& workspaces,
    const std::filesystem::path& root)
{
    for (std::size_t index = 0; index < workspaces.size(); ++index) {
        const auto destination = root / ("export_" + std::to_string(index)) / "patched.exe";
        std::filesystem::create_directories(destination.parent_path());
        auto exported = patched_export_t::export_copy(workspaces[index], destination.u8string());
        if (!exported || exported.value().bytes_written != workspaces[index]->provider().size() ||
            exported.value().patched_bytes == 0 || exported.value().patch_records == 0 ||
            exported.value().overlay_revision != workspaces[index]->overlay_revision())
            throw fixture_error_t("multi-workspace export did not apply overlay patches");
        auto original_hash = sha256_provider(workspaces[index]->provider());
        if (!original_hash)
            throw fixture_error_t(original_hash.error().message);
        auto after_hash = sha256_provider(workspaces[index]->provider());
        if (!after_hash || after_hash.value() != original_hash.value())
            throw fixture_error_t("multi-workspace export changed immutable source bytes");
    }
}

void verify_pe32_multitarget(const std::filesystem::path& root)
{
    const auto path = write_fixture32(root, "x86_multi", "x86_multi.exe", 0x3C);
    auto workspace = open_workspace(path, "x86_multi.exe");
    try {
        install_services(workspace);
        analyze_workspace(workspace, 2);
        const auto image = workspace->image();
        const auto snapshot = workspace->snapshot();
        if (!image || image->format() != format_id_t::pe32 ||
            image->architecture() != architecture_id_t::x86 ||
            !snapshot || snapshot->instructions.empty() || snapshot->functions.empty())
            throw fixture_error_t("PE32 multi-target workspace did not produce a valid baseline");
        auto decompiler = workspace->decompiler();
        if (!decompiler)
            throw fixture_error_t("PE32 multi-target decompiler service was not installed");
        auto decompiled = decompiler->decompile(snapshot->functions.front().start, {},
            workspace->cancellation_token());
        if (!decompiled || decompiled.value().binary_id != workspace->identity().binary_id() ||
            decompiled.value().function_id != snapshot->functions.front().id ||
            decompiled.value().pseudocode.find_first_not_of(" \t\r\n") == std::string::npos ||
            decompiled.value().line_to_address.empty())
            throw fixture_error_t(decompiled ?
                "PE32 multi-target decompiler returned mismatched identity" :
                decompiled.error().stable_code() + ":" + decompiled.error().message);
        overlay_transaction_request_t mutation;
        mutation.expected_revision = workspace->overlay_revision();
        overlay_operation_t comment;
        comment.kind = overlay_operation_kind_t::comment;
        comment.address = address_at(workspace, 0x1000);
        comment.text = "x86-multi-target-comment";
        mutation.operations.push_back(comment);
        auto committed = workspace->overlay()->transact(mutation, workspace->cancellation_token());
        if (!committed || !committed.value().committed)
            throw fixture_error_t("PE32 multi-target overlay commit failed");
        auto undone = workspace->overlay()->undo(workspace->overlay_revision());
        if (!undone || !undone.value().committed)
            throw fixture_error_t("PE32 multi-target overlay undo failed");
        auto redone = workspace->overlay()->redo(workspace->overlay_revision());
        if (!redone || !redone.value().committed)
            throw fixture_error_t("PE32 multi-target overlay redo failed");
        close_workspace(workspace, true);
    } catch (...) {
        try { close_workspace(workspace, true); } catch (...) {}
        throw;
    }
}

}

int main()
{
    std::vector<std::shared_ptr<aida::analysis::analysis_workspace_t>> workspaces;
    try {
        fixture_root_t root("multitarget");
        const std::vector<std::string> directories{"alpha", "beta", "gamma", "delta"};
        const std::vector<std::string> names{"duplicate.exe", "duplicate.exe", "gamma.exe", "delta.exe"};
        for (std::size_t index = 0; index < directories.size(); ++index) {
            auto path = write_fixture(root.path(), directories[index], names[index],
                                      static_cast<std::uint8_t>(20 + index));
            auto workspace = open_workspace(path, names[index]);
            install_services(workspace);
            analyze_workspace(workspace, static_cast<std::uint32_t>((index % 2) + 1));
            workspaces.push_back(std::move(workspace));
        }
        if (workspace_registry().list().size() != 4)
            throw fixture_error_t("four simultaneous workspaces were not retained");
        for (std::size_t index = 1; index < workspaces.size(); ++index) {
            if (workspaces[index]->image()->image_base() != workspaces.front()->image()->image_base())
                throw fixture_error_t("fixture image bases do not collide");
            if (workspaces[index]->identity().binary_id() == workspaces.front()->identity().binary_id())
                throw fixture_error_t("distinct workspace content collapsed to one binary identity");
        }
        if (workspaces[0]->identity().normalized_source_path() ==
            workspaces[1]->identity().normalized_source_path())
            throw fixture_error_t("duplicate basenames did not retain distinct source paths");
        target_selector_t ambiguous_selector;
        ambiguous_selector.bin_name = "duplicate.exe";
        target_resolution_options_t options;
        options.allow_unique_substring = true;
        auto ambiguous = workspace_registry().resolve(ambiguous_selector, options);
        if (ambiguous || ambiguous.error().code != workspace_error_code_t::target_ambiguous)
            throw fixture_error_t("duplicate basename resolution was not ambiguous");
        auto selected = workspace_registry().select_for_ui(workspaces.front()->identity().binary_id());
        if (!selected)
            throw fixture_error_t("UI workspace selection failed");
        const auto selected_before = workspace_registry().selected_binary_id();

        operation_overlap_gate_t initial_overlap(workspaces.size());
        std::vector<std::future<workspace_probe_t>> operations;
        for (std::size_t index = 0; index < workspaces.size(); ++index) {
            operations.push_back(std::async(std::launch::async, [&, index] {
                operation_overlap_scope_t overlap(initial_overlap);
                return exercise_workspace(workspaces[index], index);
            }));
        }
        const bool all_initial_entered = initial_overlap.release_when_ready();
        std::vector<workspace_probe_t> probes;
        for (auto& operation : operations) probes.push_back(operation.get());
        if (!all_initial_entered || initial_overlap.peak_active() != workspaces.size())
            throw fixture_error_t("four workspace service operations did not overlap");
        std::set<std::string> binary_ids;
        std::set<std::string> content_hashes;
        std::set<std::string> pseudocode_hashes;
        for (std::size_t index = 0; index < probes.size(); ++index) {
            const auto& probe = probes[index];
            binary_ids.insert(probe.binary_id.to_hex());
            content_hashes.insert(probe.content_hash.to_hex());
            pseudocode_hashes.insert(probe.pseudocode_hash.to_hex());
            if (probe.overlay_revision != 1 || probe.analysis_revision == 0 ||
                probe.history_size == 0 || probe.cache_entries == 0 ||
                probe.selection != 0x140001000ULL + index)
                throw fixture_error_t("workspace probe revision/cache/history/selection mismatch");
            const auto overlay_snapshot = workspaces[index]->overlay()->snapshot();
            bool own_comment = false;
            bool own_name = false;
            bool own_type = false;
            bool own_patch = false;
            bool own_asm_patch = false;
            bool own_int_patch = false;
            for (const auto& item : overlay_snapshot.items) {
                const auto& value = item.second;
                own_comment = own_comment || (value.kind == overlay_operation_kind_t::comment &&
                    value.text == "comment-" + std::to_string(index));
                own_name = own_name || (value.kind == overlay_operation_kind_t::name &&
                    value.name == "function_" + std::to_string(index));
                own_type = own_type || (value.kind == overlay_operation_kind_t::type_application &&
                    value.variable == "global_" + std::to_string(index));
                own_patch = own_patch || (value.kind == overlay_operation_kind_t::byte_patch &&
                    value.bytes == std::vector<std::uint8_t>{static_cast<std::uint8_t>(0xA0 + index)});
                own_asm_patch = own_asm_patch || (value.kind == overlay_operation_kind_t::assembly_patch &&
                    value.bytes == std::vector<std::uint8_t>{0x90});
                own_int_patch = own_int_patch || (value.kind == overlay_operation_kind_t::integer_patch &&
                    value.bytes == std::vector<std::uint8_t>{static_cast<std::uint8_t>(0x10 + index), 0x00});
            }
            if (!own_comment || !own_name || !own_type || !own_patch ||
                !own_asm_patch || !own_int_patch)
                throw fixture_error_t("overlay state crossed workspace identity");
        }
        if (binary_ids.size() != 4 || content_hashes.size() != 4 || pseudocode_hashes.size() != 4)
            throw fixture_error_t("workspace-local content/decompiler identities collided");
        if (workspace_registry().selected_binary_id() != selected_before)
            throw fixture_error_t("background workspace operation changed UI selection");

        verify_export_across_workspaces(workspaces, root.path());
        verify_undo_redo_across_workspaces(workspaces);
        verify_pe32_multitarget(root.path());

        auto closing = workspaces[2];
        operation_overlap_gate_t survivor_overlap(3);
        std::vector<std::future<workspace_probe_t>> surviving;
        for (const std::size_t index : {0u, 1u, 3u}) {
            surviving.push_back(std::async(std::launch::async, [&, index] {
                operation_overlap_scope_t overlap(survivor_overlap);
                return exercise_workspace(workspaces[index], index, false);
            }));
        }
        auto close_future = std::async(std::launch::async, [&] {
            close_workspace(closing, true);
            return closing->closed() && closing->cancellation_token().stop_requested();
        });
        const bool all_survivors_entered = survivor_overlap.release_when_ready();
        if (!close_future.get())
            throw fixture_error_t("closing one workspace did not cancel and drain that workspace");
        workspaces[2].reset();
        for (auto& survivor : surviving) {
            const auto probe = survivor.get();
            if (probe.overlay_revision != 1 || probe.history_size == 0)
                throw fixture_error_t("unrelated workspace work did not complete during peer close");
        }
        if (!all_survivors_entered || survivor_overlap.peak_active() != 3)
            throw fixture_error_t("surviving workspace operations did not overlap during peer close");
        for (auto& workspace : workspaces) {
            if (workspace) close_workspace(workspace, true);
        }
        workspaces.clear();
        std::cout << "workspace_multitarget_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        for (auto& workspace : workspaces) {
            try { if (workspace) close_workspace(workspace, true); } catch (...) {}
        }
        std::cerr << error.what() << '\n';
        return 1;
    }
}
