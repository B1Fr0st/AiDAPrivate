#include "static_recognition_service.hpp"

#include "type_seed_exporter.hpp"

#include "../decompiler/api_prototype_table.hpp"
#include "../workspace/workspace_registry.hpp"
#include "../../infra/taskflow_runtime.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <variant>

namespace aida::analysis::static_recognition {
namespace {

constexpr std::size_t k_max_name_records = 1000000;
constexpr std::size_t k_max_name_bytes = 240;
constexpr std::size_t k_max_prototype_records = 128000;
constexpr std::size_t k_max_vtable_slot_records = 1000000;
constexpr std::uint64_t k_max_record_payload_bytes = 32ull << 20;
constexpr std::size_t k_max_store_entries = 16;
constexpr std::size_t k_max_recovered_entries = 64;

struct store_entry_t {
    binary_id_t binary_id;
    std::uint64_t generation = 0;
    std::weak_ptr<analysis_workspace_t> workspace;
    std::shared_ptr<recognition_records_t> records;
    std::shared_ptr<cancellation_source_t> cancel_source;
    std::atomic<bool> in_flight{false};
    std::atomic<std::uint64_t> job_id{0};
    std::uint64_t touch = 0;
    std::unordered_map<std::uint64_t, std::pair<std::shared_ptr<const type_recovery_result_t>, std::uint64_t>> recovered_by_rva;
};

struct service_state_t {
    std::mutex mutex;
    std::vector<std::shared_ptr<store_entry_t>> entries;
    std::vector<std::weak_ptr<analysis_workspace_t>> attached;
    std::vector<std::shared_ptr<baseline_publish_observer_t>> observers;
    std::vector<std::shared_ptr<workspace_lifecycle_participant_t>> lifecycles;
    std::uint64_t clock = 0;
};

service_state_t& state()
{
    static service_state_t value;
    return value;
}

bool valid_name_text(const std::string& name)
{
    if (name.empty() || name.size() > k_max_name_bytes)
        return false;
    return std::all_of(name.begin(), name.end(), [](char ch) {
        return ch >= 0x20 && ch <= 0x7E;
    });
}

void append_name(recognition_records_t& records,
                 std::unordered_map<std::uint64_t, std::size_t>& emitted,
                 std::uint64_t& payload_bytes,
                 std::uint64_t rva,
                 std::string name,
                 std::string kind,
                 std::uint8_t confidence,
                 std::string source)
{
    if (emitted.find(rva) != emitted.end())
        return;
    if (!valid_name_text(name))
        return;
    if (records.names.size() >= k_max_name_records ||
        payload_bytes + name.size() + sizeof(name_out_t) > k_max_record_payload_bytes) {
        ++records.dropped_records;
        return;
    }
    emitted.emplace(rva, records.names.size());
    payload_bytes += name.size() + sizeof(name_out_t);
    name_out_t out;
    out.rva = rva;
    out.name = std::move(name);
    out.kind = std::move(kind);
    out.confidence = confidence;
    out.source = std::move(source);
    records.names.push_back(std::move(out));
}

void resolve_records(recognition_records_t& records, const analysis_snapshot_t& snapshot)
{
    std::uint64_t payload_bytes = 0;
    std::unordered_map<std::uint64_t, std::size_t> emitted;
    emitted.reserve(records.vtables.slots.size() + records.flirt.size());
    std::unordered_set<std::uint64_t> snapshot_named;
    for (const auto& symbol : snapshot.symbols)
        if (!symbol.name.empty())
            snapshot_named.insert(symbol.address.value);
    std::unordered_map<std::uint64_t, std::pair<std::string, int>> vtable_owner;
    for (const auto& type : records.rtti.types)
        for (const auto vtable_rva : type.vtable_rvas) {
            const auto found = vtable_owner.find(vtable_rva);
            if (found == vtable_owner.end() || type.score > found->second.second)
                vtable_owner[vtable_rva] = {type.name, type.score};
        }
    for (const auto& slot : records.vtables.slots) {
        vtable_slot_out_t out;
        out.vtable_rva = slot.vtable_rva;
        out.slot_index = slot.slot_index;
        out.function_rva = slot.function_rva;
        out.confidence = slot.confidence;
        const auto owner = vtable_owner.find(slot.vtable_rva);
        if (owner != vtable_owner.end()) {
            out.class_name = owner->second.first;
            out.method_name = owner->second.first + "::method_" + std::to_string(slot.slot_index);
        }
        const std::uint64_t slot_payload = static_cast<std::uint64_t>(sizeof(vtable_slot_out_t)) +
            out.class_name.size() + out.method_name.size();
        if (records.vtable_slots.size() >= k_max_vtable_slot_records ||
            payload_bytes + slot_payload > k_max_record_payload_bytes) {
            ++records.dropped_records;
            continue;
        }
        payload_bytes += slot_payload;
        records.vtable_slots.push_back(out);
        if (snapshot_named.find(slot.function_rva) != snapshot_named.end())
            continue;
        if (out.method_name.empty())
            continue;
        append_name(records, emitted, payload_bytes, slot.function_rva, out.method_name,
                    "function", slot.confidence, "rtti_vfunc");
    }
    for (const auto& match : records.flirt) {
        if (snapshot_named.find(match.rva) != snapshot_named.end())
            continue;
        if (match.tier > flirt::k_flirt_tier_exact_crc)
            continue;
        append_name(records, emitted, payload_bytes, match.rva, match.name,
                    "function", match.confidence, "flirt");
    }
    for (const auto& match : records.flirt) {
        if (snapshot_named.find(match.rva) != snapshot_named.end())
            continue;
        if (match.tier != flirt::k_flirt_tier_pattern_only)
            continue;
        append_name(records, emitted, payload_bytes, match.rva, match.name,
                    "function", match.confidence, "flirt");
    }
    for (const auto& match : records.flirt) {
        if (records.prototypes.size() >= k_max_prototype_records ||
            payload_bytes + 4096 > k_max_record_payload_bytes) {
            ++records.dropped_records;
            continue;
        }
        const auto prototype = api_prototypes::find("ucrtbase", match.name);
        if (!prototype || prototype->signature.empty())
            continue;
        prototype_out_t out;
        out.rva = match.rva;
        out.name = match.name;
        out.prototype_text.assign(prototype->signature.data(), prototype->signature.size());
        out.is_noreturn = prototype->is_noreturn || match.is_noreturn;
        out.confidence = match.confidence;
        payload_bytes += out.prototype_text.size() + sizeof(prototype_out_t);
        records.prototypes.push_back(std::move(out));
    }
}

std::shared_ptr<store_entry_t> find_entry(const binary_id_t& id, std::uint64_t generation)
{
    auto& service = state();
    for (auto& entry : service.entries)
        if (entry->binary_id == id && entry->generation == generation) {
            entry->touch = ++service.clock;
            return entry;
        }
    return {};
}

std::shared_ptr<store_entry_t> ensure_entry(const std::shared_ptr<analysis_workspace_t>& workspace,
                                            std::uint64_t generation)
{
    auto& service = state();
    const auto& id = workspace->identity().binary_id();
    if (auto existing = find_entry(id, generation))
        return existing;
    auto entry = std::make_shared<store_entry_t>();
    entry->binary_id = id;
    entry->generation = generation;
    entry->workspace = workspace;
    entry->cancel_source = std::make_shared<cancellation_source_t>();
    entry->touch = ++service.clock;
    service.entries.push_back(entry);
    while (service.entries.size() > k_max_store_entries) {
        std::size_t oldest = service.entries.size();
        for (std::size_t index = 0; index < service.entries.size(); ++index) {
            if (service.entries[index]->in_flight.load(std::memory_order_acquire))
                continue;
            if (oldest == service.entries.size() ||
                service.entries[index]->touch < service.entries[oldest]->touch)
                oldest = index;
        }
        if (oldest == service.entries.size())
            break;
        service.entries.erase(service.entries.begin() + static_cast<std::ptrdiff_t>(oldest));
    }
    return entry;
}

std::shared_ptr<const type_recovery_result_t> recovered_types_for(
    const std::shared_ptr<store_entry_t>& entry, std::uint64_t rva)
{
    if (!entry)
        return {};
    std::lock_guard lock(state().mutex);
    const auto found = entry->recovered_by_rva.find(rva);
    if (found == entry->recovered_by_rva.end())
        return {};
    found->second.second = ++state().clock;
    return found->second.first;
}

void publish_records(const std::shared_ptr<store_entry_t>& entry,
                     std::shared_ptr<recognition_records_t> records)
{
    std::lock_guard lock(state().mutex);
    records->revision = entry->records ? entry->records->revision + 1 : 1;
    entry->records = std::move(records);
}

void run_scan(const std::shared_ptr<analysis_workspace_t>& workspace,
              const std::shared_ptr<store_entry_t>& entry,
              const static_recognition_settings_t& settings)
{
    auto records = std::make_shared<recognition_records_t>();
    records->generation = entry->generation;
    records->status = k_status_running;
    const auto workspace_cancel = workspace->cancellation_token();
    const auto entry_cancel = entry->cancel_source->token();
    const auto cancelled = [&] {
        return workspace_cancel.stop_requested() || entry_cancel.stop_requested();
    };
    const auto snapshot = workspace->snapshot();
    const auto image = workspace->normalized_image();
    const auto provider = workspace->provider_handle();
    if (!snapshot || !snapshot->baseline_complete || !image || !provider) {
        records->status = k_status_failed;
        publish_records(entry, records);
        diag::log_tagged_fmt("staticrec", "scan failed gen=%llu reason=no_published_baseline",
                             static_cast<unsigned long long>(entry->generation));
        return;
    }
    if (settings.enable_flirt && !cancelled()) {
        std::shared_ptr<const flirt::flirt_signature_db_t> db =
            flirt::flirt_signature_db_t::load_embedded();
        const bool pe_x64 = image->format == format_id_t::pe32_plus &&
            image->architecture == architecture_id_t::x86_64;
        if (db && !db->empty() && pe_x64) {
            records->db_toolset = db->toolset();
            flirt::flirt_scan_request_t request;
            request.snapshot = snapshot.get();
            request.image = image.get();
            request.pe = snapshot->image.get();
            request.provider = provider;
            request.db = db.get();
            request.limits = settings.flirt_limits;
            auto scanned = flirt::flirt_scan(request, workspace_cancel);
            if (scanned) {
                auto value = scanned.take_value();
                records->flirt_status = value.status;
                records->elapsed_ms_flirt = value.elapsed_ms;
                if (value.status == flirt::k_flirt_status_completed)
                    records->flirt = std::move(value.matches);
            } else {
                records->flirt_status = flirt::k_flirt_status_invalid;
            }
        } else {
            records->flirt_status = flirt::k_flirt_status_db_absent;
        }
        diag::log_tagged_fmt("staticrec",
            "flirt complete gen=%llu matches=%zu status=%u elapsed_ms=%.1f",
            static_cast<unsigned long long>(entry->generation),
            records->flirt.size(),
            static_cast<unsigned int>(records->flirt_status),
            records->elapsed_ms_flirt);
    } else {
        records->flirt_status = flirt::k_flirt_status_db_absent;
    }
    if (settings.enable_rtti && !cancelled()) {
        auto scanned = re::rtti::scan_static_image(*image, *provider, settings.rtti_limits,
                                                   workspace_cancel);
        if (scanned) {
            records->rtti = scanned.take_value();
            records->elapsed_ms_rtti = records->rtti.elapsed_ms;
        } else {
            records->rtti.status = re::rtti::k_static_rtti_no_rtti;
        }
        diag::log_tagged_fmt("staticrec",
            "rtti complete gen=%llu types=%zu status=%u elapsed_ms=%.1f",
            static_cast<unsigned long long>(entry->generation),
            records->rtti.types.size(),
            static_cast<unsigned int>(records->rtti.status),
            records->elapsed_ms_rtti);
    }
    if (settings.enable_vmt && !cancelled() &&
        records->rtti.status == re::rtti::k_static_rtti_completed) {
        std::vector<std::uint64_t> starts;
        starts.reserve(snapshot->functions.size());
        for (const auto& function : snapshot->functions)
            starts.push_back(function.start.value);
        std::sort(starts.begin(), starts.end());
        auto scanned = re::vmt::extract_slots_static(*image, *provider, records->rtti, &starts,
                                                     workspace_cancel);
        if (scanned) {
            records->vtables = scanned.take_value();
            records->elapsed_ms_vmt = records->vtables.elapsed_ms;
        } else {
            records->vtables.status = re::vmt::k_static_vtables_no_vtables;
        }
        diag::log_tagged_fmt("staticrec",
            "vmt complete gen=%llu slots=%zu status=%u elapsed_ms=%.1f",
            static_cast<unsigned long long>(entry->generation),
            records->vtables.slots.size(),
            static_cast<unsigned int>(records->vtables.status),
            records->elapsed_ms_vmt);
    }
    if (!cancelled())
        resolve_records(*records, *snapshot);
    if (cancelled()) {
        records->status = k_status_partial;
    } else if (records->dropped_records != 0) {
        records->status = k_status_partial;
    } else if (!records->names.empty() || !records->prototypes.empty() ||
               !records->vtable_slots.empty()) {
        records->status = k_status_complete;
    } else if (records->flirt_status == flirt::k_flirt_status_db_absent &&
               records->rtti.types.empty() && records->vtables.slots.empty()) {
        records->status = k_status_db_absent;
    } else if (records->rtti.types.empty() && records->vtables.slots.empty()) {
        records->status = k_status_no_rtti;
    } else {
        records->status = k_status_complete;
    }
    publish_records(entry, records);
    diag::log_tagged_fmt("staticrec",
        "scan complete gen=%llu flirt=%zu rtti=%zu slots=%zu names=%zu prototypes=%zu status=%u dropped=%llu",
        static_cast<unsigned long long>(entry->generation),
        records->flirt.size(),
        records->rtti.types.size(),
        records->vtables.slots.size(),
        records->names.size(),
        records->prototypes.size(),
        static_cast<unsigned int>(records->status),
        static_cast<unsigned long long>(records->dropped_records));
}

bool kick_scan(const std::shared_ptr<analysis_workspace_t>& workspace, std::uint64_t generation)
{
    std::shared_ptr<store_entry_t> entry;
    std::shared_ptr<recognition_records_t> published;
    {
        std::lock_guard lock(state().mutex);
        entry = ensure_entry(workspace, generation);
        published = entry->records;
    }
    if (published && published->revision != 0)
        return false;
    bool expected = false;
    if (!entry->in_flight.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return false;
    infra::taskflow_runtime::task_descriptor_t desc;
    desc.domain = infra::taskflow_runtime::executor_domain_t::feature_worker;
    desc.owner_subsystem = "analysis_workspace";
    desc.label = "static_recognition.scan";
    desc.shutdown_policy = "drain";
    desc.body = [workspace, entry] {
        run_scan(workspace, entry, static_recognition_settings_t{});
        entry->in_flight.store(false, std::memory_order_release);
    };
    desc.cancel_hook = [entry] {
        entry->cancel_source->request_cancel();
    };
    auto submitted = infra::taskflow_runtime::submit(std::move(desc));
    if (!submitted.submitted) {
        diag::log_tagged_fmt("staticrec", "scan submit rejected gen=%llu reason=%s",
                             static_cast<unsigned long long>(generation),
                             submitted.reject_reason.c_str());
        entry->in_flight.store(false, std::memory_order_release);
        return false;
    }
    entry->job_id.store(submitted.handle.id, std::memory_order_release);
    return true;
}

class static_recognition_lifecycle_t final : public workspace_lifecycle_participant_t {
public:
    explicit static_recognition_lifecycle_t(binary_id_t id) : id_(id) {}

    void request_cancel() noexcept override
    {
        std::vector<std::shared_ptr<store_entry_t>> entries;
        {
            std::lock_guard lock(state().mutex);
            entries = state().entries;
        }
        for (auto& entry : entries) {
            if (entry->binary_id != id_)
                continue;
            entry->cancel_source->request_cancel();
            const auto job = entry->job_id.load(std::memory_order_acquire);
            if (job != 0)
                infra::taskflow_runtime::cancel(infra::taskflow_runtime::job_handle_t{job});
        }
    }

    workspace_result_t<void> drain(std::chrono::steady_clock::time_point deadline) override
    {
        for (;;) {
            bool any_in_flight = false;
            {
                std::lock_guard lock(state().mutex);
                for (const auto& entry : state().entries)
                    if (entry->binary_id == id_ && entry->in_flight.load(std::memory_order_acquire))
                        any_in_flight = true;
            }
            if (!any_in_flight)
                return workspace_result_t<void>::success();
            if (std::chrono::steady_clock::now() >= deadline) {
                auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                    "static recognition did not drain before the workspace deadline",
                    "static_recognition.drain");
                error.deadline = true;
                return workspace_result_t<void>::failure(std::move(error));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    }

private:
    binary_id_t id_;
};

class static_recognition_observer_t final : public baseline_publish_observer_t {
public:
    void on_baseline_published(
        const std::shared_ptr<const analysis_publication_t>& publication) noexcept override
    {
        try {
            if (!publication || publication->readiness != workspace_readiness_t::baseline_ready ||
                !publication->snapshot || !publication->snapshot->baseline_complete)
                return;
            auto workspace = workspace_registry().find_by_binary_id(publication->binary_id);
            if (!workspace || workspace->target_kind() != target_kind_t::static_file ||
                workspace->generation() != publication->generation)
                return;
            kick_scan(workspace, publication->generation);
        } catch (...) {
            diag::log_tagged_fmt("staticrec", "publish observer error");
        }
    }
};

}

void ensure_attached(const std::shared_ptr<analysis_workspace_t>& workspace)
{
    if (!workspace)
        return;
    auto& service = state();
    std::lock_guard lock(service.mutex);
    for (auto it = service.attached.begin(); it != service.attached.end();) {
        if (it->expired())
            it = service.attached.erase(it);
        else
            ++it;
    }
    for (const auto& weak : service.attached) {
        if (weak.lock() == workspace)
            return;
    }
    auto observer = std::make_shared<static_recognition_observer_t>();
    auto observed = workspace->register_baseline_publish_observer(observer);
    if (!observed) {
        diag::log_tagged_fmt("staticrec", "observer registration failed error=%s",
                             observed.error().message.c_str());
        return;
    }
    auto lifecycle = std::make_shared<static_recognition_lifecycle_t>(
        workspace->identity().binary_id());
    auto registered = workspace->register_lifecycle_participant(lifecycle);
    if (!registered) {
        diag::log_tagged_fmt("staticrec", "lifecycle registration failed error=%s",
                             registered.error().message.c_str());
        return;
    }
    service.observers.push_back(std::move(observer));
    service.lifecycles.push_back(std::move(lifecycle));
    service.attached.push_back(workspace);
}

workspace_result_t<std::shared_ptr<const recognition_records_t>>
run_for_workspace(std::shared_ptr<analysis_workspace_t> workspace,
                  const static_recognition_settings_t& settings,
                  const cancellation_token_t& cancel)
{
    if (!workspace)
        return workspace_result_t<std::shared_ptr<const recognition_records_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_required,
                                 "static recognition requires a workspace",
                                 "static_recognition.run"));
    ensure_attached(workspace);
    const std::uint64_t generation = workspace->generation();
    std::shared_ptr<store_entry_t> entry;
    std::shared_ptr<recognition_records_t> published;
    {
        std::lock_guard lock(state().mutex);
        entry = ensure_entry(workspace, generation);
        published = entry->records;
    }
    if (published && published->revision != 0 &&
        published->status != k_status_pending &&
        published->status != k_status_running &&
        published->status != k_status_failed)
        return workspace_result_t<std::shared_ptr<const recognition_records_t>>::success(
            std::const_pointer_cast<const recognition_records_t>(published));
    bool expected = false;
    if (entry->in_flight.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        run_scan(workspace, entry, settings);
        entry->in_flight.store(false, std::memory_order_release);
    } else {
        while (entry->in_flight.load(std::memory_order_acquire)) {
            if (cancel.stop_requested())
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    }
    {
        std::lock_guard lock(state().mutex);
        published = entry->records;
    }
    if (published)
        return workspace_result_t<std::shared_ptr<const recognition_records_t>>::success(
            std::const_pointer_cast<const recognition_records_t>(published));
    return workspace_result_t<std::shared_ptr<const recognition_records_t>>::failure(
        make_workspace_error(workspace_error_code_t::integrity_failure,
                             "static recognition produced no records",
                             "static_recognition.run"));
}

std::shared_ptr<const recognition_records_t>
records_for(const std::shared_ptr<analysis_workspace_t>& workspace)
{
    if (!workspace)
        return {};
    ensure_attached(workspace);
    const std::uint64_t generation = workspace->generation();
    std::shared_ptr<store_entry_t> entry;
    std::shared_ptr<recognition_records_t> published;
    {
        std::lock_guard lock(state().mutex);
        entry = find_entry(workspace->identity().binary_id(), generation);
        if (entry)
            published = entry->records;
    }
    if (!entry) {
        const auto publication = workspace->analysis_publication();
        if (publication && publication->readiness == workspace_readiness_t::baseline_ready &&
            publication->snapshot && publication->snapshot->baseline_complete &&
            workspace->target_kind() == target_kind_t::static_file)
            kick_scan(workspace, generation);
        return {};
    }
    return std::const_pointer_cast<const recognition_records_t>(published);
}

std::vector<type_graph::type_seed_batch_t>
type_seed_batches_for(const std::shared_ptr<analysis_workspace_t>& workspace,
                      const decompiler_entity_key_t& entity,
                      std::uint64_t generation,
                      std::uint8_t min_confidence)
{
    const auto records = records_for(workspace);
    if (!records || records->status == k_status_pending || records->status == k_status_running)
        return {};
    std::shared_ptr<const type_recovery_result_t> recovered;
    if (entity.kind == decompiler_entity_kind_t::native_function) {
        const auto* native = std::get_if<native_decompiler_entity_identity_t>(&entity.identity);
        if (native && native->entry.space == address_space_id_t::relative_virtual &&
            native->entry.value != 0) {
            std::shared_ptr<store_entry_t> entry;
            {
                std::lock_guard lock(state().mutex);
                entry = find_entry(workspace->identity().binary_id(), generation);
            }
            recovered = recovered_types_for(entry, native->entry.value);
        }
    }
    type_seed_export_options_t options;
    options.min_confidence = min_confidence;
    auto batches = make_recognition_seed_batches(*records, entity, generation, options,
                                                 recovered.get());
    if (!batches)
        return {};
    return batches.take_value();
}

recognition_wait_result_t wait_for_records(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    std::chrono::milliseconds timeout)
{
    recognition_wait_result_t out;
    if (!workspace)
        return out;
    ensure_attached(workspace);
    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + timeout;
    for (;;) {
        auto records = records_for(workspace);
        if (records && records->status != k_status_pending &&
            records->status != k_status_running) {
            out.records = std::move(records);
            out.ready = true;
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            out.records = std::move(records);
            out.timed_out = true;
            break;
        }
        std::this_thread::sleep_for((std::min)(std::chrono::milliseconds(10), timeout));
    }
    out.waited_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    return out;
}

library_exclusion_set_t build_library_exclusion(
    const recognition_records_t& records,
    const analysis_snapshot_t& snapshot)
{
    library_exclusion_set_t exclusion;
    if (records.flirt.empty())
        return exclusion;
    std::unordered_set<std::uint64_t> snapshot_named;
    snapshot_named.reserve(snapshot.symbols.size());
    for (const auto& symbol : snapshot.symbols)
        if (!symbol.name.empty())
            snapshot_named.insert(symbol.address.value);
    exclusion.rvas.reserve(records.flirt.size() * 2);
    for (const auto& match : records.flirt) {
        if (match.tier > flirt::k_flirt_tier_exact_crc)
            continue;
        ++exclusion.tier_candidates;
        if (snapshot_named.find(match.rva) != snapshot_named.end()) {
            ++exclusion.suppressed_named;
            continue;
        }
        exclusion.rvas.insert(match.rva);
    }
    return exclusion;
}

bool is_library_function(const library_exclusion_set_t& exclusion,
                         std::uint64_t rva) noexcept
{
    return exclusion.rvas.find(rva) != exclusion.rvas.end();
}

void note_recovered_types(
    const std::shared_ptr<analysis_workspace_t>& workspace,
    std::uint64_t function_rva,
    std::uint64_t generation,
    std::shared_ptr<const type_recovery_result_t> recovered)
{
    if (!workspace || !recovered)
        return;
    ensure_attached(workspace);
    auto& service = state();
    std::lock_guard lock(service.mutex);
    auto entry = ensure_entry(workspace, generation);
    auto& slot = entry->recovered_by_rva[function_rva];
    slot.first = std::move(recovered);
    slot.second = ++service.clock;
    while (entry->recovered_by_rva.size() > k_max_recovered_entries) {
        auto oldest = entry->recovered_by_rva.begin();
        for (auto it = entry->recovered_by_rva.begin(); it != entry->recovered_by_rva.end(); ++it)
            if (it->second.second < oldest->second.second)
                oldest = it;
        entry->recovered_by_rva.erase(oldest);
    }
}

}
