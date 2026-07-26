#include "overlay_lifecycle_harness.hpp"

#include "../analysis_workspace/workspace_fixture_builder.hpp"
#include "../../src/core/analysis/workspace/search_index.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <process.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {

struct harness_log_t {
    using clock_t = std::chrono::steady_clock;
    static unsigned long pid() { return static_cast<unsigned long>(_getpid()); }
    static unsigned long tid() { return static_cast<unsigned long>(std::hash<std::thread::id>{}(std::this_thread::get_id())); }
    static std::uint64_t epoch_ms() { return std::chrono::duration_cast<std::chrono::milliseconds>(clock_t::now().time_since_epoch()).count(); }
    static void emit(const char* test, const char* phase, const char* status, std::uint64_t elapsed_ms, const std::string& detail = {}) {
        std::fprintf(stderr, "[C03-HARNESS] test=%s phase=%s status=%s elapsed=%llums pid=%lu tid=%lu errno=%d detail=%s\n",
            test, phase, status, static_cast<unsigned long long>(elapsed_ms), pid(), tid(), static_cast<int>(errno),
            detail.empty() ? "-" : detail.c_str());
        std::fflush(stderr);
    }
};

namespace {

using namespace test_fixture;

void require(bool condition, const char* message)
{
    if (!condition) {
        harness_log_t::emit("overlay_lifecycle", "assertion", "fail", 0, message);
        throw fixture_error_t(message);
    }
}

address_t fixture_address(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    std::uint64_t rva)
{
    address_t address;
    address.space = address_space_id_t::virtual_address;
    address.value = workspace->normalized_image()->image_base + rva;
    address.architecture = workspace->identity().architecture();
    address.mode = workspace->identity().architecture_mode();
    return address;
}

std::optional<std::uint64_t> address_rva(
    const workspace_image_t& image, const address_t& address)
{
    if (address.space == address_space_id_t::relative_virtual)
        return address.value;
    if (address.space == address_space_id_t::virtual_address &&
        address.value >= image.image_base)
        return address.value - image.image_base;
    return std::nullopt;
}

std::uint64_t provider_offset_for_rva(
    const workspace_image_t& image, std::uint64_t rva)
{
    for (const auto& mapping : image.address_mappings) {
        if (mapping.source_space != address_space_id_t::file_offset ||
            mapping.target_space != address_space_id_t::relative_virtual ||
            rva < mapping.target_start ||
            rva >= mapping.target_start + mapping.size)
            continue;
        return mapping.source_start + rva - mapping.target_start;
    }
    throw fixture_error_t("fixture RVA has no provider mapping");
}

std::uint8_t provider_byte(const byte_provider_t& provider,
                           std::uint64_t offset)
{
    std::uint8_t value = 0;
    const auto read = provider.read_exact(offset, &value, 1);
    if (!read)
        throw fixture_error_t(
            read.error().stable_code() + ":" + read.error().message);
    return value;
}

const function_record_t* find_function(
    const analysis_snapshot_t& snapshot, std::uint64_t rva)
{
    if (!snapshot.normalized_image)
        return nullptr;
    const auto found = std::find_if(
        snapshot.functions.begin(), snapshot.functions.end(),
        [&](const auto& function) {
            const auto value = address_rva(
                *snapshot.normalized_image, function.start);
            return value && *value == rva;
        });
    return found == snapshot.functions.end() ? nullptr : &*found;
}

bool coverage_contains(const analysis_snapshot_t& snapshot,
                       std::uint64_t rva, coverage_reason_t reason)
{
    if (!snapshot.normalized_image)
        return false;
    return std::any_of(snapshot.coverage.begin(), snapshot.coverage.end(),
        [&](const auto& span) {
            const auto start = address_rva(
                *snapshot.normalized_image, span.start);
            return start && span.reason == reason && rva >= *start &&
                rva - *start < span.size;
        });
}

overlay_operation_t operation(
    overlay_operation_kind_t kind,
    const std::shared_ptr<analysis_workspace_t>& workspace,
    std::uint64_t rva)
{
    overlay_operation_t value;
    value.kind = kind;
    value.address = fixture_address(workspace, rva);
    return value;
}

void verify_bounded_failures(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    const auto generation = workspace->generation();
    const auto analysis_revision = workspace->analysis_revision();
    const auto overlay_revision = workspace->overlay_revision();

    overlay_transaction_request_t cancelled_request;
    cancelled_request.expected_revision = overlay_revision;
    auto cancelled_comment = operation(
        overlay_operation_kind_t::comment, workspace, 0x1020);
    cancelled_comment.text = "cancelled";
    cancelled_request.operations.push_back(std::move(cancelled_comment));
    cancellation_source_t cancelled;
    cancelled.request_cancel();
    const auto cancelled_result = workspace->overlay()->transact(
        cancelled_request, cancelled.token());
    require(!cancelled_result &&
            cancelled_result.error().code == workspace_error_code_t::cancelled,
            "pre-cancelled overlay transaction did not fail closed");

    cancellation_source_t expired(std::chrono::steady_clock::now());
    const auto expired_result = workspace->overlay()->transact(
        cancelled_request, expired.token());
    require(!expired_result &&
            expired_result.error().code ==
                workspace_error_code_t::deadline_exceeded,
            "expired overlay transaction did not preserve deadline semantics");

    overlay_transaction_request_t oversized_request;
    oversized_request.expected_revision = overlay_revision;
    auto oversized = operation(
        overlay_operation_kind_t::byte_patch, workspace, 0x1020);
    oversized.bytes.assign((1U << 20U) + 1U, 0x90);
    oversized_request.operations.push_back(std::move(oversized));
    const auto oversized_result = workspace->overlay()->transact(
        oversized_request);
    require(!oversized_result &&
            oversized_result.error().code ==
                workspace_error_code_t::limit_exceeded,
            "oversized overlay patch did not respect the item budget");
    require(workspace->generation() == generation &&
            workspace->analysis_revision() == analysis_revision &&
            workspace->overlay_revision() == overlay_revision &&
            workspace->overlay()->snapshot().items.empty(),
            "rejected overlay work changed workspace state");
}

void verify_persisted_candidate(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    auto loaded = workspace->database()->load_snapshot(
        workspace->normalized_image(), workspace->image(),
        workspace->cancellation_token());
    require(loaded && loaded.value(),
            "atomic overlay publication did not persist a snapshot");
    require(loaded.value()->generation == workspace->generation() &&
            loaded.value()->analysis_revision ==
                workspace->analysis_revision() &&
            loaded.value()->overlay_revision == workspace->overlay_revision(),
            "persisted overlay snapshot revisions diverged from publication");
}

void restore_persisted_publication(
    const std::shared_ptr<analysis_workspace_t>& workspace)
{
    auto loaded = workspace->database()->load_snapshot(
        workspace->normalized_image(), workspace->image(),
        workspace->cancellation_token());
    require(loaded && loaded.value(),
            "warm reopen did not load the committed overlay snapshot");
    auto snapshot = loaded.take_value();
    require(snapshot->generation == workspace->generation() &&
            snapshot->analysis_revision == 1 &&
            snapshot->overlay_revision == workspace->overlay_revision() &&
            !snapshot->baseline_complete,
            "warm reopen snapshot lost selective invalidation state");
    auto products = workspace->database()->load_search_products(
        snapshot->generation, snapshot->analysis_revision,
        snapshot->overlay_revision, workspace->cancellation_token());
    require(static_cast<bool>(products),
            "warm reopen did not load committed search products");
    auto restored = restore_persisted_search_index(
        snapshot, products.take_value(),
        std::make_shared<analysis_metrics_t>(snapshot->generation), {},
        workspace->cancellation_token());
    require(static_cast<bool>(restored),
            "warm reopen did not restore the committed search index");
    auto published = workspace->publish_analysis_bundle(
        workspace->generation(), workspace->analysis_revision(), snapshot,
        restored.take_value(), false);
    require(published && workspace->snapshot() && workspace->search_index(),
            "warm reopen did not publish the committed selective snapshot");
}

}

void run_overlay_lifecycle_harness()
{
    const auto harness_start = harness_log_t::epoch_ms();
    harness_log_t::emit("overlay_lifecycle", "harness", "enter", 0, "fixture=overlay_lifecycle");
    fixture_root_t root("overlay_lifecycle");
    const auto first_path = write_bytes_fixture(
        root.path() / "first" / "overlay.exe",
        analysis_contract_pe64(0x41));
    const auto second_path = write_bytes_fixture(
        root.path() / "second" / "overlay.exe",
        analysis_contract_pe64(0x42));
    std::shared_ptr<analysis_workspace_t> first;
    std::shared_ptr<analysis_workspace_t> second;
    std::shared_ptr<analysis_workspace_t> reopened;
    std::string first_database_path;
    try {
        const auto setup_start = harness_log_t::epoch_ms();
        harness_log_t::emit("overlay_lifecycle", "fixture_setup", "enter", 0);
        first = open_workspace(first_path, "overlay-first.exe");
        second = open_workspace(second_path, "overlay-second.exe");
        install_services(first);
        install_services(second);
        analyze_workspace(first, 1);
        analyze_workspace(second, 1);
        first_database_path = first->database()->path();
        harness_log_t::emit("overlay_lifecycle", "fixture_setup", "pass", harness_log_t::epoch_ms() - setup_start);

        const auto bounded_start = harness_log_t::epoch_ms();
        harness_log_t::emit("overlay_lifecycle", "verify_bounded_failures", "enter", 0);
        verify_bounded_failures(first);
        harness_log_t::emit("overlay_lifecycle", "verify_bounded_failures", "pass", harness_log_t::epoch_ms() - bounded_start);
        const auto before = first->snapshot();
        require(before && before->baseline_complete,
                "overlay fixture baseline was not complete");
        const auto* affected = find_function(*before, 0x1000);
        const auto* unaffected = find_function(*before, 0x1020);
        require(affected && unaffected,
                "overlay fixture did not recover both functions");
        const auto affected_id = affected->id;
        const auto unaffected_id = unaffected->id;
        const auto original_generation = first->generation();
        const auto original_analysis_revision = first->analysis_revision();
        const auto second_generation = second->generation();
        const auto second_analysis_revision = second->analysis_revision();
        const auto second_counts = std::make_pair(
            second->snapshot()->instructions.size(),
            second->snapshot()->functions.size());
        const auto file_offset = provider_offset_for_rva(
            *first->normalized_image(), 0x1000);
        const auto original_byte = provider_byte(
            first->source_provider(), file_offset);

        const auto transaction_start = harness_log_t::epoch_ms();
        harness_log_t::emit("overlay_lifecycle", "overlay_transaction", "enter", 0);
        overlay_transaction_request_t request;
        request.expected_revision = 0;
        request.idempotency_key = "overlay-lifecycle-byte-patch";
        auto patch = operation(
            overlay_operation_kind_t::byte_patch, first, 0x1000);
        patch.bytes = {0x90};
        request.operations.push_back(std::move(patch));
        const auto committed = first->overlay()->transact(request);
        require(committed && committed.value().committed &&
                committed.value().revision == 1,
                "real overlay transaction did not commit revision one");
        require(first->generation() == original_generation + 1 &&
                first->analysis_revision() == original_analysis_revision &&
                first->overlay_revision() == 1,
                "overlay publication revisions were not monotonic");
        require(provider_byte(first->provider(), file_offset) == 0x90 &&
                provider_byte(first->source_provider(), file_offset) ==
                    original_byte,
                "overlay publication did not isolate projected and immutable bytes");

        const auto after = first->snapshot();
        require(after && !after->baseline_complete &&
                !find_function(*after, 0x1000) &&
                find_function(*after, 0x1020) &&
                find_function(*after, 0x1020)->id == unaffected_id &&
                std::none_of(after->functions.begin(), after->functions.end(),
                    [&](const auto& function) {
                        return function.id == affected_id;
                    }),
                "selective publication did not retire only the affected function closure");
        require(coverage_contains(*after, 0x1000,
                                  coverage_reason_t::pending) &&
                coverage_contains(*after, 0x1020,
                                  coverage_reason_t::decoded),
                "selective publication did not preserve exact coverage state");
        verify_persisted_candidate(first);
        harness_log_t::emit("overlay_lifecycle", "overlay_transaction", "pass", harness_log_t::epoch_ms() - transaction_start);

        require(second->generation() == second_generation &&
                second->analysis_revision() == second_analysis_revision &&
                second->overlay_revision() == 0 &&
                second->overlay()->snapshot().items.empty() &&
                std::make_pair(second->snapshot()->instructions.size(),
                               second->snapshot()->functions.size()) ==
                    second_counts,
                "overlay mutation crossed the workspace isolation boundary");

        const auto undo_redo_start = harness_log_t::epoch_ms();
        harness_log_t::emit("overlay_lifecycle", "undo_redo", "enter", 0);
        const auto undone = first->overlay()->undo(
            first->overlay_revision());
        require(undone && undone.value().committed &&
                first->overlay()->snapshot().items.empty() &&
                provider_byte(first->provider(), file_offset) == original_byte,
                "overlay undo did not restore immutable projected bytes");
        verify_persisted_candidate(first);
        const auto redone = first->overlay()->redo(
            first->overlay_revision());
        require(redone && redone.value().committed &&
                first->overlay()->snapshot().items.size() == 1 &&
                provider_byte(first->provider(), file_offset) == 0x90,
                "overlay redo did not restore projected patch bytes");
        verify_persisted_candidate(first);
        harness_log_t::emit("overlay_lifecycle", "undo_redo", "pass", harness_log_t::epoch_ms() - undo_redo_start);

        const auto persisted_generation = first->generation();
        const auto persisted_revision = first->overlay_revision();
        close_workspace(first);
        first.reset();

        const auto reopen_start = harness_log_t::epoch_ms();
        harness_log_t::emit("overlay_lifecycle", "warm_reopen", "enter", 0);
        reopened = open_workspace(first_path, "overlay-first.exe");
        install_services(reopened);
        require(reopened->generation() == persisted_generation &&
                reopened->overlay_revision() == persisted_revision &&
                reopened->overlay()->snapshot().items.size() == 1 &&
                provider_byte(reopened->provider(), file_offset) == 0x90,
                "overlay warm reopen did not restore generation, journal, and bytes");
        restore_persisted_publication(reopened);
        require(find_function(*reopened->snapshot(), 0x1020) &&
                !find_function(*reopened->snapshot(), 0x1000),
                "overlay warm reopen lost selective analysis facts");

        close_workspace(reopened, true);
        reopened.reset();
        close_workspace(second, true);
        second.reset();
        harness_log_t::emit("overlay_lifecycle", "warm_reopen", "pass", harness_log_t::epoch_ms() - reopen_start);
        harness_log_t::emit("overlay_lifecycle", "harness", "pass", harness_log_t::epoch_ms() - harness_start);
    } catch (...) {
        harness_log_t::emit("overlay_lifecycle", "harness", "fail", harness_log_t::epoch_ms() - harness_start, "exception propagated from test body");
        try {
            if (reopened)
                close_workspace(reopened, true);
            if (first)
                close_workspace(first, true);
            else if (!first_database_path.empty())
                remove_database_artifacts(first_database_path);
            if (second)
                close_workspace(second, true);
        } catch (...) {
        }
        throw;
    }
}

}

int main()
{
    const auto main_start = aida::analysis::c03_test::harness_log_t::epoch_ms();
    aida::analysis::c03_test::harness_log_t::emit("overlay_lifecycle", "main", "enter", 0);
    try {
        aida::analysis::c03_test::run_overlay_lifecycle_harness();
        const auto elapsed = aida::analysis::c03_test::harness_log_t::epoch_ms() - main_start;
        aida::analysis::c03_test::harness_log_t::emit("overlay_lifecycle", "main", "pass", elapsed);
        std::cout << "overlay_lifecycle_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& exception) {
        const auto elapsed = aida::analysis::c03_test::harness_log_t::epoch_ms() - main_start;
        aida::analysis::c03_test::harness_log_t::emit("overlay_lifecycle", "main", "fail", elapsed, exception.what());
        std::cerr << exception.what() << '\n';
        return 1;
    }
}
