#include "pe_baseline_analyzer.hpp"

#include "checked_range.hpp"
#include "persistence_queue.hpp"
#include "workspace_database.hpp"
#include "../decode/x86_tile_decoder.hpp"
#include "../provider_snapshot.hpp"

#include <algorithm>
#include <array>
#include <condition_variable>
#include <future>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <queue>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kInstructionEntityTag = 1ULL << 56;
constexpr std::uint64_t kStringEntityTag = 6ULL << 56;
constexpr std::uint64_t kSymbolEntityTag = 7ULL << 56;
constexpr std::uint64_t kTypeEntityTag = 10ULL << 56;

class phase_completion_guard_t final {
public:
    phase_completion_guard_t(analysis_metrics_t& metrics, phase_measurement_t& measurement) noexcept
        : metrics_(metrics), measurement_(measurement) {}

    ~phase_completion_guard_t() {
        if (measurement_.active)
            metrics_.end_phase(measurement_, 0, 0, 0, 0, true);
    }

private:
    analysis_metrics_t& metrics_;
    phase_measurement_t& measurement_;
};

struct decode_work_t {
    std::uint64_t rva = 0;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::uint64_t stable_source_id = 0;
};

struct decode_work_less_t {
    bool operator()(const decode_work_t& lhs, const decode_work_t& rhs) const noexcept {
        if (lhs.rva != rhs.rva)
            return lhs.rva > rhs.rva;
        if (provenance_rank(lhs.provenance) != provenance_rank(rhs.provenance))
            return provenance_rank(lhs.provenance) < provenance_rank(rhs.provenance);
        if (lhs.confidence != rhs.confidence)
            return lhs.confidence < rhs.confidence;
        return lhs.stable_source_id > rhs.stable_source_id;
    }
};

struct decoded_candidate_t {
    instruction_record_t instruction;
    std::uint64_t rva = 0;
    std::uint64_t end_rva = 0;
    std::uint32_t source_lane = 0;
};

struct decode_lane_output_t {
    std::vector<decoded_candidate_t> candidates;
    std::vector<operand_fact_t> operands;
    std::vector<target_fact_t> targets;
};

struct image_file_mapping_t {
    std::uint64_t provider_offset = 0;
    std::uint64_t available_bytes = 0;
};

struct image_range_t {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::uint32_t permissions = image_permission_none;
};

bool stronger_decode_work(const decode_work_t& lhs, const decode_work_t& rhs) noexcept {
    if (provenance_rank(lhs.provenance) != provenance_rank(rhs.provenance))
        return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
    if (lhs.confidence != rhs.confidence)
        return lhs.confidence > rhs.confidence;
    return lhs.stable_source_id < rhs.stable_source_id;
}

address_t rva_address(const workspace_image_t& image, std::uint64_t rva) noexcept {
    return {address_space_id_t::relative_virtual, rva, image.architecture,
        image.architecture_mode};
}

std::optional<std::uint64_t> to_rva(const workspace_image_t& image,
                                    const address_t& address) noexcept {
    if (address.architecture != image.architecture ||
        address.mode != image.architecture_mode)
        return std::nullopt;
    if (address.space == address_space_id_t::relative_virtual)
        return address.value < image.image_size ? std::optional<std::uint64_t>(address.value)
                                                : std::nullopt;
    if ((address.space == address_space_id_t::virtual_address ||
         address.space == address_space_id_t::live_virtual) &&
        address.value >= image.image_base) {
        const auto rva = address.value - image.image_base;
        return rva < image.image_size ? std::optional<std::uint64_t>(rva) : std::nullopt;
    }
    return std::nullopt;
}

std::vector<image_range_t> image_ranges(const workspace_image_t& image) {
    std::vector<image_range_t> ranges;
    const auto append = [&ranges, &image](const auto& region) {
        const auto extent = std::max(region.virtual_size, region.file_size);
        std::uint64_t end = 0;
        if (extent == 0 || !checked_add_u64(region.virtual_address, extent, end) ||
            end > image.image_size)
            return;
        ranges.push_back({region.virtual_address, end, region.permissions});
    };
    if (!image.sections.empty()) {
        for (const auto& section : image.sections)
            append(section);
    } else {
        for (const auto& segment : image.segments)
            append(segment);
    }
    std::sort(ranges.begin(), ranges.end(), [](const image_range_t& lhs, const image_range_t& rhs) {
        if (lhs.start != rhs.start)
            return lhs.start < rhs.start;
        if (lhs.end != rhs.end)
            return lhs.end < rhs.end;
        return lhs.permissions < rhs.permissions;
    });
    return ranges;
}

std::vector<image_range_t> executable_ranges(const workspace_image_t& image) {
    auto ranges = image_ranges(image);
    ranges.erase(std::remove_if(ranges.begin(), ranges.end(), [](const image_range_t& range) {
        return (range.permissions & image_permission_execute) == 0;
    }), ranges.end());
    return ranges;
}

bool executable_rva(const workspace_image_t& image, std::uint64_t rva) {
    const auto ranges = executable_ranges(image);
    const auto found = std::upper_bound(ranges.begin(), ranges.end(), rva,
        [](std::uint64_t value, const image_range_t& range) { return value < range.start; });
    if (found == ranges.begin())
        return false;
    const auto& range = *std::prev(found);
    return rva >= range.start && rva < range.end;
}

bool supports_x86_tile_decode(const arch_decoder_registration_t& registration) noexcept {
    const auto& key = registration.key;
    if (key.architecture == architecture_id_t::x86 &&
        (key.mode == architecture_mode_t::x86_16 || key.mode == architecture_mode_t::x86_32))
        return registration.implementation_id == "zydis.x86";
    return key.architecture == architecture_id_t::x86_64 &&
           key.mode == architecture_mode_t::x86_64 &&
           registration.implementation_id == "zydis.x86_64";
}

std::optional<image_file_mapping_t> file_mapping(const workspace_image_t& image,
    std::uint64_t rva) noexcept {
    for (const auto& mapping : image.address_mappings) {
        if (mapping.source_space != address_space_id_t::file_offset ||
            mapping.target_space != address_space_id_t::relative_virtual ||
            rva < mapping.target_start || rva - mapping.target_start >= mapping.size)
            continue;
        std::uint64_t offset = 0;
        if (!checked_add_u64(mapping.source_start, rva - mapping.target_start, offset) ||
            offset >= image.provider_size)
            continue;
        return image_file_mapping_t{offset,
            std::min(mapping.size - (rva - mapping.target_start), image.provider_size - offset)};
    }
    const auto find_region = [&image, rva](const auto& regions)
        -> std::optional<image_file_mapping_t> {
        for (const auto& region : regions) {
            if (rva < region.virtual_address || rva - region.virtual_address >= region.file_size)
                continue;
            std::uint64_t offset = 0;
            if (!checked_add_u64(region.file_offset, rva - region.virtual_address, offset) ||
                offset >= image.provider_size)
                continue;
            return image_file_mapping_t{offset,
                std::min(region.file_size - (rva - region.virtual_address),
                    image.provider_size - offset)};
        }
        return std::nullopt;
    };
    auto section = find_region(image.sections);
    return section ? section : find_region(image.segments);
}

std::uint64_t stable_mix(std::uint64_t lhs, std::uint64_t rhs) noexcept {
    auto value = lhs ^ (rhs + 0x9e3779b97f4a7c15ULL + (lhs << 6) + (lhs >> 2));
    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

workspace_error_t cancellation_error(const cancellation_token_t& local,
    const cancellation_token_t& workspace, const char* phase) {
    if (local.deadline_exceeded() || workspace.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "baseline analysis deadline exceeded", phase);
        error.deadline = true;
        error.cancellation = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "baseline analysis cancelled", phase);
    error.cancellation = true;
    return error;
}

bool padding_byte(std::uint8_t value) noexcept {
    return value == 0 || value == 0x90 || value == 0xCC;
}

bool append_coverage(std::vector<coverage_span_t>& coverage, coverage_span_t span,
    std::uint64_t maximum_spans) {
    if (span.size == 0)
        return true;
    if (coverage.size() >= maximum_spans)
        return false;
    coverage.push_back(std::move(span));
    return true;
}

workspace_result_t<void> validate_coverage_linear_cancellable(
    const analysis_snapshot_t& snapshot, const cancellation_token_t& cancel) {
    if (!snapshot.normalized_image) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "coverage validation requires a normalized image", "search_index"));
    }
    const auto ranges = executable_ranges(*snapshot.normalized_image);
    std::size_t span_index = 0;
    for (const auto& range : ranges) {
        std::uint64_t cursor = range.start;
        while (span_index < snapshot.coverage.size()) {
            if (cancel.stop_requested())
                return workspace_result_t<void>::failure(cancellation_error(cancel, cancel, "search_index"));
            const auto& span = snapshot.coverage[span_index];
            if (span.start.space != address_space_id_t::relative_virtual) {
                ++span_index;
                continue;
            }
            std::uint64_t end = 0;
            if (!checked_add_u64(span.start.value, span.size, end)) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "coverage span overflows during validation", "search_index"));
            }
            if (end <= range.start) {
                ++span_index;
                continue;
            }
            if (span.start.value >= range.end)
                break;
            if (span.start.value != cursor || end > range.end || span.size == 0 ||
                span.reason == coverage_reason_t::pending) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "executable coverage contains a gap, overlap, or pending span", "search_index"));
            }
            cursor = end;
            ++span_index;
        }
        if (cursor != range.end) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "executable coverage is incomplete", "search_index"));
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::uint64_t> snapshot_memory_bytes(const analysis_snapshot_t& snapshot) {
    std::uint64_t total = sizeof(snapshot);
    const auto add = [&total](std::uint64_t count, std::uint64_t size)
        -> workspace_result_t<void> {
        std::uint64_t bytes = 0;
        std::uint64_t updated = 0;
        if (!checked_mul_u64(count, size, bytes) || !checked_add_u64(total, bytes, updated)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "analysis memory accounting overflows", "memory_budget"));
        }
        total = updated;
        return workspace_result_t<void>::success();
    };
    const std::array<std::pair<std::uint64_t, std::uint64_t>, 12> allocations{{
        {snapshot.instructions.capacity(), sizeof(instruction_record_t)},
        {snapshot.operand_facts.capacity(), sizeof(operand_fact_t)},
        {snapshot.target_facts.capacity(), sizeof(target_fact_t)},
        {snapshot.blocks.capacity(), sizeof(basic_block_record_t)},
        {snapshot.function_chunks.capacity(), sizeof(function_chunk_record_t)},
        {snapshot.function_block_memberships.capacity(), sizeof(function_block_membership_record_t)},
        {snapshot.functions.capacity(), sizeof(function_record_t)},
        {snapshot.edges.capacity(), sizeof(edge_record_t)},
        {snapshot.xrefs.capacity(), sizeof(xref_record_t)},
        {snapshot.strings.capacity(), sizeof(string_record_t)},
        {snapshot.symbols.capacity(), sizeof(symbol_record_t)},
        {snapshot.coverage.capacity(), sizeof(coverage_span_t)}
    }};
    for (const auto& allocation : allocations) {
        auto added = add(allocation.first, allocation.second);
        if (!added)
            return workspace_result_t<std::uint64_t>::failure(added.error());
    }
    for (const auto& string : snapshot.strings) {
        auto added = add(string.value.capacity(), 1);
        if (!added)
            return workspace_result_t<std::uint64_t>::failure(added.error());
    }
    for (const auto& symbol : snapshot.symbols) {
        auto added = add(symbol.name.capacity(), 1);
        if (!added)
            return workspace_result_t<std::uint64_t>::failure(added.error());
    }
    return workspace_result_t<std::uint64_t>::success(total);
}

std::string hex_rva(std::uint64_t value) {
    std::ostringstream out;
    out << std::hex << value;
    return out.str();
}

std::uint64_t saturated_product(std::uint64_t lhs, std::uint64_t rhs,
                                std::uint64_t ceiling) noexcept {
    std::uint64_t value = 0;
    return checked_mul_u64(lhs, rhs, value) && value < ceiling ? value : ceiling;
}

} 

workspace_result_t<void> baseline_analysis_settings_t::validate() const {
    if (max_seed_count == 0 || max_decode_queue == 0 || max_decoded_instructions == 0 ||
        max_coverage_spans == 0 || max_analysis_memory_bytes == 0 ||
        decode_read_window_bytes == 0 || decode_read_window_bytes > 64ULL * 1024ULL * 1024ULL ||
        string_read_window_bytes == 0 || string_read_window_bytes > 64ULL * 1024ULL * 1024ULL ||
        max_string_scan_bytes == 0 || max_string_value_bytes < minimum_string_length ||
        max_strings == 0 || max_trace_instructions == 0 || cancellation_check_interval == 0 ||
        string_cancellation_interval_bytes == 0 || minimum_string_length == 0 ||
        decode_worker_lanes > 64 || task_priority < 0 || task_priority > 7 ||
        function_limits.max_blocks == 0 || function_limits.max_functions == 0 ||
        function_limits.max_function_memberships == 0 || function_limits.max_edges == 0 ||
        function_limits.max_switches == 0 || function_limits.max_result_bytes == 0 ||
        function_limits.max_result_bytes > max_analysis_memory_bytes ||
        function_limits.max_blocks_per_function == 0 ||
        function_limits.cancellation_check_interval == 0 || xref_limits.max_xrefs == 0 ||
        xref_limits.max_data_candidates == 0 || xref_limits.max_result_bytes == 0 ||
        xref_limits.max_result_bytes > max_analysis_memory_bytes ||
        xref_limits.read_window_bytes == 0 ||
        xref_limits.read_window_bytes > 64ULL * 1024ULL * 1024ULL ||
        xref_limits.cancellation_check_interval == 0 || search_limits.max_entries == 0 ||
        search_limits.max_index_bytes == 0 || search_limits.max_index_bytes > max_analysis_memory_bytes ||
        search_limits.max_query_bytes == 0 || search_limits.max_results_per_query == 0 ||
        search_limits.cancellation_check_interval == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "baseline analysis settings are outside supported safety bounds", "settings"));
    }
    return workspace_result_t<void>::success();
}

std::string baseline_analysis_settings_t::canonical_json() const {
    std::ostringstream out;
    out << "{\"version\":2"
        << ",\"max_seed_count\":" << max_seed_count
        << ",\"max_decode_queue\":" << max_decode_queue
        << ",\"max_decoded_instructions\":" << max_decoded_instructions
        << ",\"max_coverage_spans\":" << max_coverage_spans
        << ",\"max_analysis_memory_bytes\":" << max_analysis_memory_bytes
        << ",\"decode_read_window_bytes\":" << decode_read_window_bytes
        << ",\"string_read_window_bytes\":" << string_read_window_bytes
        << ",\"max_string_scan_bytes\":" << max_string_scan_bytes
        << ",\"max_string_value_bytes\":" << max_string_value_bytes
        << ",\"max_strings\":" << max_strings
        << ",\"decode_worker_lanes\":" << decode_worker_lanes
        << ",\"max_trace_instructions\":" << max_trace_instructions
        << ",\"cancellation_check_interval\":" << cancellation_check_interval
        << ",\"string_cancellation_interval_bytes\":" << string_cancellation_interval_bytes
        << ",\"minimum_string_length\":" << minimum_string_length
        << ",\"scan_utf8\":" << (scan_utf8 ? "true" : "false")
        << ",\"scan_utf16\":" << (scan_utf16 ? "true" : "false")
        << ",\"task_priority\":" << task_priority
        << ",\"pe_profile\":{\"max_sections\":" << pe_limits.max_sections
        << ",\"max_imports\":" << pe_limits.max_imports
        << ",\"max_exports\":" << pe_limits.max_exports
        << ",\"max_relocations\":" << pe_limits.max_relocations << "}"
        << ",\"function\":{\"max_blocks\":" << function_limits.max_blocks
        << ",\"max_functions\":" << function_limits.max_functions
        << ",\"max_edges\":" << function_limits.max_edges
        << ",\"max_result_bytes\":" << function_limits.max_result_bytes << "}"
        << ",\"xref\":{\"max_xrefs\":" << xref_limits.max_xrefs
        << ",\"max_data_candidates\":" << xref_limits.max_data_candidates
        << ",\"max_pointer_scan_bytes\":" << xref_limits.max_pointer_scan_bytes
        << ",\"max_result_bytes\":" << xref_limits.max_result_bytes << "}"
        << ",\"search\":{\"max_entries\":" << search_limits.max_entries
        << ",\"max_index_bytes\":" << search_limits.max_index_bytes << "}}";
    return out.str();
}

struct pe_baseline_analyzer_t::impl_t {
    std::shared_ptr<analysis_workspace_t> workspace;
    baseline_analysis_settings_t settings;
    std::uint64_t expected_generation = 0;
    std::uint64_t expected_analysis_revision = 0;
    cancellation_source_t cancellation;
    std::shared_ptr<analysis_metrics_t> metrics;
    std::shared_ptr<const workspace_image_t> image;
    arch_decoder_key_t decoder_key;
    std::shared_ptr<analysis_snapshot_t> draft;
    std::shared_ptr<const analysis_snapshot_t> final_snapshot;
    std::vector<function_seed_t> seeds;
    std::map<std::pair<std::uint64_t, std::uint8_t>, std::size_t> seed_index_by_evidence;
    std::mutex seeds_mutex;
    std::priority_queue<decode_work_t, std::vector<decode_work_t>, decode_work_less_t> decode_queue;
    std::unordered_map<std::uint64_t, decode_work_t> best_queued;
    std::unordered_map<std::uint64_t, decode_work_t> claimed;
    std::mutex decode_mutex;
    std::condition_variable decode_cv;
    std::size_t active_decoders = 0;
    bool decode_finished = false;
    bool decode_stop = false;
    std::optional<workspace_error_t> decode_error;
    std::vector<decode_lane_output_t> lane_outputs;
    std::shared_ptr<provider_snapshot_t> x86_tile_snapshot;
    std::mutex x86_tile_snapshot_mutex;
    std::atomic<std::uint64_t> decode_candidate_count{0};
    std::atomic<std::uint64_t> decode_storage_bytes{0};
    std::vector<std::uint64_t> undecodable_rvas;
    std::mutex undecodable_mutex;
    block_recovery_result_t block_result;
    function_recovery_result_t function_result;
    function_recovery_limits_t effective_function_limits;
    xref_build_result_t xref_result;
    std::vector<type_candidate_record_t> type_candidates;
    std::shared_ptr<search_index_t> search;
    persistence_ticket_t persistence_ticket;
    std::mutex failure_mutex;
    std::optional<workspace_error_t> first_failure;

    impl_t(std::shared_ptr<analysis_workspace_t> value, baseline_analysis_settings_t configured,
        std::uint64_t generation, std::uint64_t analysis_revision,
        std::optional<std::chrono::steady_clock::time_point> deadline)
        : workspace(std::move(value)), settings(std::move(configured)),
          expected_generation(generation), expected_analysis_revision(analysis_revision),
          cancellation(deadline), metrics(std::make_shared<analysis_metrics_t>(generation)),
          effective_function_limits(settings.function_limits) {
        auto lanes = settings.decode_worker_lanes;
        if (lanes == 0) {
            const auto hardware = std::max(1U, std::thread::hardware_concurrency());
            lanes = std::min(16U, std::max(2U, hardware));
        }
        lane_outputs.resize(lanes);
    }

    workspace_result_t<void> ensure_active(const std::atomic<bool>& runtime_cancel,
        const char* phase) {
        if (workspace->generation() != expected_generation) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::stale_generation,
                "workspace generation changed during baseline analysis", phase));
        }
        if (runtime_cancel.load(std::memory_order_acquire) ||
            workspace->cancellation_token().stop_requested())
            cancellation.request_cancel();
        const auto local = cancellation.token();
        const auto workspace_token = workspace->cancellation_token();
        if (local.stop_requested() || workspace_token.stop_requested())
            return workspace_result_t<void>::failure(cancellation_error(local, workspace_token, phase));
        if (workspace->closing() || workspace->closed()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::workspace_closing, "workspace is closing", phase));
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> update_progress(const char* phase, std::uint64_t complete,
        std::uint64_t total, std::uint64_t complete_bytes, std::uint64_t total_bytes,
        workspace_readiness_t readiness = workspace_readiness_t::analyzing) {
        workspace_progress_t progress;
        progress.readiness = readiness;
        progress.phase = phase;
        progress.completed_units = complete;
        progress.total_units = total;
        progress.completed_bytes = complete_bytes;
        progress.total_bytes = total_bytes;
        progress.cancellation_requested = cancellation.token().stop_requested();
        return workspace->update_progress(expected_generation, std::move(progress));
    }

    bool reserve_decode_storage(std::uint64_t bytes) noexcept {
        auto current = decode_storage_bytes.load(std::memory_order_acquire);
        for (;;) {
            if (current > settings.max_analysis_memory_bytes ||
                bytes > settings.max_analysis_memory_bytes - current)
                return false;
            if (decode_storage_bytes.compare_exchange_weak(current, current + bytes,
                    std::memory_order_acq_rel, std::memory_order_acquire))
                return true;
        }
    }

    bool enqueue_decode(decode_work_t work) {
        if (!image || !executable_rva(*image, work.rva))
            return true;
        std::lock_guard<std::mutex> lock(decode_mutex);
        const auto found = best_queued.find(work.rva);
        if (found != best_queued.end() && !stronger_decode_work(work, found->second))
            return true;
        if (decode_queue.size() >= settings.max_decode_queue ||
            !reserve_decode_storage(sizeof(decode_work_t) * 2ULL)) {
            decode_error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                "decode work queue exceeds analysis budget", "decode");
            decode_stop = true;
            decode_cv.notify_all();
            return false;
        }
        best_queued[work.rva] = work;
        decode_queue.push(work);
        decode_cv.notify_one();
        return true;
    }

    bool add_function_seed(function_seed_t seed) {
        if (!image || !executable_rva(*image, seed.address.value))
            return true;
        std::lock_guard<std::mutex> lock(seeds_mutex);
        const auto key = std::make_pair(seed.address.value, static_cast<std::uint8_t>(seed.kind));
        const auto found = seed_index_by_evidence.find(key);
        if (found != seed_index_by_evidence.end()) {
            auto& current = seeds[found->second];
            if (stronger_decode_work({seed.address.value, seed.provenance, seed.confidence,
                    seed.stable_source_id}, {current.address.value, current.provenance,
                    current.confidence, current.stable_source_id}))
                current = std::move(seed);
            return true;
        }
        if (seeds.size() >= settings.max_seed_count ||
            !reserve_decode_storage(sizeof(function_seed_t) * 2ULL + seed.name.capacity()))
            return false;
        seed_index_by_evidence.emplace(key, seeds.size());
        seeds.push_back(std::move(seed));
        return true;
    }

    std::optional<workspace_error_t> current_decode_error() {
        std::lock_guard<std::mutex> lock(decode_mutex);
        return decode_error;
    }

    void discard_persistence_candidate() noexcept {
        const auto candidate = persistence_ticket.snapshot_candidate;
        if (!candidate)
            return;
        try {
            (void)candidate->discard();
        } catch (...) {
        }
    }

    std::uint64_t executable_bytes() const noexcept {
        if (!image)
            return 0;
        std::uint64_t total = 0;
        for (const auto& range : executable_ranges(*image)) {
            std::uint64_t updated = 0;
            if (!checked_add_u64(total, range.end - range.start, updated))
                return std::numeric_limits<std::uint64_t>::max();
            total = updated;
        }
        return total;
    }
};

pe_baseline_analyzer_t::pe_baseline_analyzer_t(std::unique_ptr<impl_t> impl) : impl_(std::move(impl)) {}
pe_baseline_analyzer_t::~pe_baseline_analyzer_t() = default;

workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>> pe_baseline_analyzer_t::create(
    std::shared_ptr<analysis_workspace_t> workspace, baseline_analysis_settings_t settings,
    std::uint64_t expected_generation, std::uint64_t expected_analysis_revision,
    std::optional<std::chrono::steady_clock::time_point> deadline) {
    if (!workspace) {
        return workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument, "baseline analyzer requires a workspace", "create"));
    }
    auto valid = settings.validate();
    if (!valid)
        return workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>>::failure(valid.error());
    if (workspace->target_kind() != target_kind_t::static_file) {
        return workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>>::failure(make_workspace_error(
            workspace_error_code_t::live_target_bulk_analysis_unsupported,
            "bulk baseline analysis is not supported for live targets", "create"));
    }
    if (workspace->generation() != expected_generation) {
        return workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>>::failure(make_workspace_error(
            workspace_error_code_t::stale_generation,
            "workspace generation changed before analysis submission", "create"));
    }
    if (workspace->analysis_revision() != expected_analysis_revision ||
        expected_analysis_revision == std::numeric_limits<std::uint64_t>::max()) {
        return workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "workspace analysis revision changed before submission", "create"));
    }
    return workspace_result_t<std::shared_ptr<pe_baseline_analyzer_t>>::success(
        std::shared_ptr<pe_baseline_analyzer_t>(new pe_baseline_analyzer_t(
            std::make_unique<impl_t>(std::move(workspace), std::move(settings),
                expected_generation, expected_analysis_revision, deadline))));
}

std::uint32_t pe_baseline_analyzer_t::decode_lane_count() const noexcept {
    return static_cast<std::uint32_t>(impl_->lane_outputs.size());
}

std::uint64_t pe_baseline_analyzer_t::expected_generation() const noexcept {
    return impl_->expected_generation;
}

std::shared_ptr<analysis_metrics_t> pe_baseline_analyzer_t::metrics() const noexcept {
    return impl_->metrics;
}

workspace_result_t<void> pe_baseline_analyzer_t::parse_phase(const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::parse);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto active = impl_->ensure_active(runtime_cancel, "parse");
    if (!active) {
        impl_->metrics->end_phase(measurement, 0, 0, 0, 1, true);
        return active;
    }
    impl_->image = impl_->workspace->normalized_image();
    if (!impl_->image) {
        impl_->metrics->end_phase(measurement, 0, 0, 0, 1, true);
        auto error = make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "baseline analysis requires a registry-admitted normalized image", "parse");
        error.details.emplace_back("missing_parser_symbol",
            "workspace_registry_t::admit_verified_provider");
        error.details.emplace_back("missing_parser_file", "workspace_registry.hpp");
        return workspace_result_t<void>::failure(std::move(error));
    }
    auto validated = validate_workspace_image(*impl_->image, {}, true, impl_->cancellation.token());
    if (!validated) {
        impl_->metrics->end_phase(measurement, impl_->workspace->provider().size(), 0, 1, 1, true);
        return validated;
    }
    impl_->decoder_key = make_arch_decoder_key(*impl_->image);
    auto decoder = default_arch_decoder_registry().resolve(impl_->decoder_key);
    if (!decoder) {
        auto error = decoder.error();
        if (error.code == workspace_error_code_t::unsupported_format) {
            error.details.emplace_back("missing_registry_symbol",
                "arch_decoder_registry_t::register_decoder");
            error.details.emplace_back("missing_registry_file", "arch_decoder.hpp");
        }
        impl_->metrics->end_phase(measurement, impl_->workspace->provider().size(), 0, 1, 1, true);
        return workspace_result_t<void>::failure(std::move(error));
    }
    impl_->draft = std::make_shared<analysis_snapshot_t>();
    impl_->draft->binary_id = impl_->workspace->identity().binary_id();
    impl_->draft->load_profile_hash = impl_->workspace->identity().load_profile_hash();
    impl_->draft->generation = impl_->expected_generation;
    impl_->draft->analysis_revision = impl_->expected_analysis_revision + 1;
    impl_->draft->overlay_revision = impl_->workspace->overlay_revision();
    impl_->draft->normalized_image = impl_->image;
    impl_->draft->image = impl_->workspace->image();
    impl_->metrics->set(analysis_metric_t::file_bytes, impl_->workspace->provider().size());
    impl_->metrics->set(analysis_metric_t::executable_bytes, impl_->executable_bytes());
    impl_->metrics->add(analysis_metric_t::provider_revalidations);
    auto progress = impl_->update_progress("parse", 1, 1, impl_->workspace->provider().size(),
        impl_->workspace->provider().size(), workspace_readiness_t::parsed);
    impl_->metrics->end_phase(measurement, impl_->workspace->provider().size(),
        impl_->image->image_size, 1, 1, !progress.has_value());
    return progress;
}

workspace_result_t<void> pe_baseline_analyzer_t::seed_phase(const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::seed);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto active = impl_->ensure_active(runtime_cancel, "seed");
    if (!active) {
        impl_->metrics->end_phase(measurement, 0, 0, 0, 1, true);
        return active;
    }
    if (!impl_->image || !impl_->draft) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "parse phase did not retain a normalized image", "seed"));
    }
    std::map<std::pair<std::uint64_t, std::uint8_t>, function_seed_t> candidates;
    const auto add = [&](const address_t& address, function_seed_kind_t kind,
        fact_provenance_t provenance, std::uint8_t confidence, std::uint64_t source,
        std::optional<address_t> known_end, std::string name, bool noreturn)
        -> workspace_result_t<void> {
        const auto rva = to_rva(*impl_->image, address);
        if (!rva || !executable_rva(*impl_->image, *rva))
            return workspace_result_t<void>::success();
        function_seed_t seed;
        seed.address = rva_address(*impl_->image, *rva);
        if (known_end) {
            const auto end = to_rva(*impl_->image, *known_end);
            if (end && *end > *rva)
                seed.known_end = rva_address(*impl_->image, *end);
        }
        seed.kind = kind;
        seed.provenance = provenance;
        seed.confidence = confidence;
        seed.stable_source_id = source;
        seed.name = std::move(name);
        seed.noreturn = noreturn;
        const auto key = std::make_pair(*rva, static_cast<std::uint8_t>(kind));
        const auto found = candidates.find(key);
        if (found == candidates.end() || stronger_decode_work({*rva, seed.provenance,
                seed.confidence, seed.stable_source_id}, {*rva, found->second.provenance,
                found->second.confidence, found->second.stable_source_id}))
            candidates[key] = std::move(seed);
        if (candidates.size() > impl_->settings.max_seed_count) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "function seed count exceeds analysis budget", "seed"));
        }
        return workspace_result_t<void>::success();
    };
    std::uint64_t source = 1;
    for (const auto& entry : impl_->image->entry_points) {
        auto added = add(entry.address, function_seed_kind_t::image_entry,
            fact_provenance_t::image_entry, 100, source++, std::nullopt, entry.provenance, false);
        if (!added)
            return added;
    }
    for (const auto& exported : impl_->image->exports) {
        if (exported.forwarder)
            continue;
        auto added = add(exported.address, function_seed_kind_t::export_entry,
            fact_provenance_t::export_entry, 100, source++, std::nullopt,
            exported.name.value_or(std::string{}), false);
        if (!added)
            return added;
    }
    for (const auto& symbol : impl_->image->symbols) {
        if (!symbol.defined || (symbol.kind != image_symbol_kind_t::function &&
            symbol.kind != image_symbol_kind_t::debug_symbol))
            continue;
        auto added = add(symbol.address, function_seed_kind_t::debug_symbol,
            fact_provenance_t::debug_symbol, 95, source++, std::nullopt, symbol.name, false);
        if (!added)
            return added;
    }
    for (const auto& relocation : impl_->image->relocations) {
        if (!relocation.target)
            continue;
        auto added = add(*relocation.target, function_seed_kind_t::relocation_target,
            fact_provenance_t::relocation, 70, source++, std::nullopt, {}, false);
        if (!added)
            return added;
    }
    const auto prior = impl_->workspace->snapshot();
    if (prior && prior->generation == impl_->expected_generation) {
        for (const auto& symbol : prior->symbols) {
            if (symbol.kind != symbol_kind_t::function && symbol.kind != symbol_kind_t::debug_symbol)
                continue;
            auto added = add(symbol.address, function_seed_kind_t::debug_symbol,
                symbol.provenance, symbol.confidence, source++, std::nullopt, symbol.name, false);
            if (!added)
                return added;
        }
    }
    {
        std::lock_guard<std::mutex> lock(impl_->seeds_mutex);
        impl_->seeds.clear();
        impl_->seed_index_by_evidence.clear();
        impl_->seeds.reserve(candidates.size());
        for (auto& candidate : candidates) {
            impl_->seed_index_by_evidence.emplace(candidate.first, impl_->seeds.size());
            impl_->seeds.push_back(std::move(candidate.second));
        }
    }
    for (const auto& seed : impl_->seeds) {
        if (!impl_->enqueue_decode({seed.address.value, seed.provenance, seed.confidence,
                seed.stable_source_id})) {
            std::lock_guard<std::mutex> lock(impl_->decode_mutex);
            return workspace_result_t<void>::failure(*impl_->decode_error);
        }
    }
    auto progress = impl_->update_progress("seed", impl_->seeds.size(), impl_->seeds.size(), 0,
        impl_->executable_bytes());
    impl_->metrics->end_phase(measurement, 0, impl_->seeds.size() * sizeof(function_seed_t),
        impl_->seeds.size(), 1, !progress.has_value());
    return progress;
}

workspace_result_t<void> pe_baseline_analyzer_t::decode_lane_phase(std::uint32_t lane,
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::decode);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    if (lane >= impl_->lane_outputs.size()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument, "decode lane index is invalid", "decode"));
    }
    auto active = impl_->ensure_active(runtime_cancel, "decode");
    if (!active)
        return active;
    auto registration = default_arch_decoder_registry().resolve(impl_->decoder_key);
    if (!registration)
        return workspace_result_t<void>::failure(registration.error());
    arch_decode_budget_t budget;
    budget.max_decode_attempts = std::min(arch_decode_budget_t::hard_max_decode_attempts,
        impl_->settings.max_decoded_instructions);
    budget.max_instructions = std::min(arch_decode_budget_t::hard_max_instructions,
        impl_->settings.max_decoded_instructions);
    budget.max_input_bytes = saturated_product(impl_->settings.max_decoded_instructions,
        registration.value().limits.maximum_instruction_bytes,
        arch_decode_budget_t::hard_max_input_bytes);
    budget.max_operand_facts = saturated_product(impl_->settings.max_decoded_instructions,
        registration.value().limits.maximum_operand_facts,
        arch_decode_budget_t::hard_max_operand_facts);
    budget.max_target_facts = saturated_product(impl_->settings.max_decoded_instructions,
        registration.value().limits.maximum_target_facts,
        arch_decode_budget_t::hard_max_target_facts);
    const bool use_x86_tile_decoder = supports_x86_tile_decode(registration.value());
    std::unique_ptr<worker_owned_arch_decoder_t> decoder;
    std::unique_ptr<decode::worker_owned_x86_tile_decoder_t> x86_tile_decoder;
    std::shared_ptr<provider_snapshot_t> x86_tile_snapshot;
    if (use_x86_tile_decoder) {
        std::lock_guard<std::mutex> lock(impl_->x86_tile_snapshot_mutex);
        if (!impl_->x86_tile_snapshot) {
            const auto& provider = impl_->workspace->provider_handle();
            auto snapshot = provider->identity().immutable_snapshot
                ? provider_snapshot_t::capture(provider, impl_->expected_generation,
                    impl_->cancellation.token())
                : provider_snapshot_t::materialize(provider, {}, impl_->cancellation.token());
            if (!snapshot)
                return workspace_result_t<void>::failure(snapshot.error());
            impl_->x86_tile_snapshot = snapshot.take_value();
        }
        x86_tile_snapshot = impl_->x86_tile_snapshot;
        auto tile_decoder = decode::worker_owned_x86_tile_decoder_t::create(
            impl_->decoder_key.mode);
        if (!tile_decoder)
            return workspace_result_t<void>::failure(tile_decoder.error());
        x86_tile_decoder = tile_decoder.take_value();
    } else {
        auto decoder_result = default_arch_decoder_registry().create_worker(impl_->decoder_key,
            budget, impl_->cancellation.token());
        if (!decoder_result)
            return workspace_result_t<void>::failure(decoder_result.error());
        decoder = decoder_result.take_value();
    }
    arch_decode_result_t decoded;
    auto& output = impl_->lane_outputs[lane];
    std::uint64_t requested = 0;
    std::uint64_t tile_input_bytes = 0;
    std::uint64_t tile_decoded_bytes = 0;
    std::uint64_t tile_instructions = 0;
    std::uint64_t checks = 0;
    for (;;) {
        decode_work_t work;
        {
            std::unique_lock<std::mutex> lock(impl_->decode_mutex);
            for (;;) {
                if (impl_->decode_stop || impl_->decode_error)
                    break;
                if (!impl_->decode_queue.empty()) {
                    work = impl_->decode_queue.top();
                    impl_->decode_queue.pop();
                    ++impl_->active_decoders;
                    break;
                }
                if (impl_->active_decoders == 0) {
                    impl_->decode_finished = true;
                    impl_->decode_cv.notify_all();
                    break;
                }
                impl_->decode_cv.wait_for(lock, std::chrono::milliseconds(2));
                if (runtime_cancel.load(std::memory_order_acquire)) {
                    impl_->decode_stop = true;
                    impl_->cancellation.request_cancel();
                    impl_->decode_cv.notify_all();
                }
            }
            if (impl_->decode_error)
                return workspace_result_t<void>::failure(*impl_->decode_error);
            if (impl_->decode_stop || impl_->decode_finished)
                break;
        }
        const auto finish = [&] {
            std::lock_guard<std::mutex> lock(impl_->decode_mutex);
            if (impl_->active_decoders != 0)
                --impl_->active_decoders;
            if (impl_->decode_queue.empty() && impl_->active_decoders == 0)
                impl_->decode_finished = true;
            impl_->decode_cv.notify_all();
        };
        auto current = work.rva;
        std::uint32_t trace = 0;
        const auto accept_decoded = [&](const arch_decode_result_t& value,
            const image_file_mapping_t& mapping, const arch_decode_request_t& request) -> bool {
            decoded_candidate_t candidate;
            candidate.instruction = value.instruction;
            candidate.rva = current;
            candidate.source_lane = lane;
            if (candidate.instruction.length == 0 || !checked_add_u64(current,
                    candidate.instruction.length, candidate.end_rva) ||
                !workspace_image_span_within(current, candidate.instruction.length,
                    impl_->image->image_size) ||
                candidate.instruction.length > mapping.available_bytes) {
                std::lock_guard<std::mutex> lock(impl_->undecodable_mutex);
                impl_->undecodable_rvas.push_back(current);
                return false;
            }
            for (std::uint16_t index = 0; index < value.target_count; ++index) {
                const auto& target = value.targets[index];
                if (!target.direct || (target.kind != target_kind_record_t::branch &&
                    target.kind != target_kind_record_t::call))
                    continue;
                const auto target_rva = to_rva(*impl_->image, target.target);
                if (!target_rva)
                    continue;
                const auto target_provenance = target.kind == target_kind_record_t::call
                    ? fact_provenance_t::call_target : fact_provenance_t::recursive_decode;
                const auto source_id = stable_mix(request.stable_source_id, *target_rva);
                if (!impl_->enqueue_decode({*target_rva, target_provenance,
                        target.kind == target_kind_record_t::call ? 90U : 95U, source_id}))
                    return false;
                if (target.kind == target_kind_record_t::call) {
                    function_seed_t seed;
                    seed.address = rva_address(*impl_->image, *target_rva);
                    seed.kind = function_seed_kind_t::direct_call_target;
                    seed.provenance = fact_provenance_t::call_target;
                    seed.confidence = 90;
                    seed.stable_source_id = source_id;
                    if (!impl_->add_function_seed(std::move(seed))) {
                        std::lock_guard<std::mutex> lock(impl_->decode_mutex);
                        impl_->decode_error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                            "dynamic function seeds exceed analysis budget", "decode");
                        impl_->decode_stop = true;
                        return false;
                    }
                }
            }
            if (impl_->current_decode_error())
                return false;
            if (value.operand_count > value.operands.size() ||
                value.target_count > value.targets.size() ||
                output.operands.size() > std::numeric_limits<std::uint32_t>::max() -
                    value.operand_count ||
                output.targets.size() > std::numeric_limits<std::uint32_t>::max() -
                    value.target_count) {
                std::lock_guard<std::mutex> lock(impl_->decode_mutex);
                impl_->decode_error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "decode output exceeds analysis budget", "decode");
                impl_->decode_stop = true;
                return false;
            }
            std::uint64_t batch_bytes = sizeof(decoded_candidate_t) * 2ULL;
            std::uint64_t fact_bytes = 0;
            if (!checked_mul_u64(value.operand_count, sizeof(operand_fact_t), fact_bytes) ||
                !checked_add_u64(batch_bytes, fact_bytes, batch_bytes) ||
                !checked_mul_u64(value.target_count, sizeof(target_fact_t), fact_bytes) ||
                !checked_add_u64(batch_bytes, fact_bytes, batch_bytes) ||
                !impl_->reserve_decode_storage(batch_bytes)) {
                std::lock_guard<std::mutex> lock(impl_->decode_mutex);
                impl_->decode_error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "decode fact storage exceeds analysis memory budget", "decode");
                impl_->decode_stop = true;
                return false;
            }
            const auto count = impl_->decode_candidate_count.fetch_add(1, std::memory_order_acq_rel);
            if (count >= impl_->settings.max_decoded_instructions) {
                impl_->decode_candidate_count.fetch_sub(1, std::memory_order_acq_rel);
                std::lock_guard<std::mutex> lock(impl_->decode_mutex);
                impl_->decode_error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "decoded instruction count exceeds analysis budget", "decode");
                impl_->decode_stop = true;
                return false;
            }
            candidate.instruction.operand_fact_begin = static_cast<std::uint32_t>(output.operands.size());
            candidate.instruction.operand_fact_count = value.operand_count;
            candidate.instruction.target_fact_begin = static_cast<std::uint32_t>(output.targets.size());
            candidate.instruction.target_fact_count = value.target_count;
            output.operands.insert(output.operands.end(), value.operands.begin(),
                value.operands.begin() + value.operand_count);
            output.targets.insert(output.targets.end(), value.targets.begin(),
                value.targets.begin() + value.target_count);
            output.candidates.push_back(std::move(candidate));
            const auto flags = output.candidates.back().instruction.flow_flags;
            if ((flags & (flow_return | flow_interrupt | flow_terminal)) != 0 ||
                ((flags & flow_branch) != 0 && (flags & flow_fallthrough) == 0))
                return false;
            current = output.candidates.back().end_rva;
            work.provenance = fact_provenance_t::recursive_decode;
            work.confidence = std::min<std::uint8_t>(work.confidence, 95);
            work.stable_source_id = stable_mix(work.stable_source_id, current);
            return true;
        };
        for (;;) {
            if (++checks >= impl_->settings.cancellation_check_interval) {
                checks = 0;
                active = impl_->ensure_active(runtime_cancel, "decode");
                if (!active) {
                    finish();
                    return active;
                }
            }
            if (++trace > impl_->settings.max_trace_instructions) {
                auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "recursive decode trace exceeds analysis budget", "decode");
                {
                    std::lock_guard<std::mutex> lock(impl_->decode_mutex);
                    impl_->decode_error = error;
                    impl_->decode_stop = true;
                }
                break;
            }
            {
                std::lock_guard<std::mutex> lock(impl_->decode_mutex);
                const auto claimed = impl_->claimed.find(current);
                if (claimed != impl_->claimed.end() && !stronger_decode_work(work, claimed->second))
                    break;
                if (impl_->claimed.size() >= impl_->settings.max_decoded_instructions ||
                    !impl_->reserve_decode_storage(sizeof(decode_work_t) * 2ULL)) {
                    impl_->decode_error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "decode claim storage exceeds analysis budget", "decode");
                    impl_->decode_stop = true;
                    break;
                }
                impl_->claimed[current] = work;
            }
            if (!executable_rva(*impl_->image, current))
                break;
            const auto mapping = file_mapping(*impl_->image, current);
            if (!mapping || mapping->available_bytes <
                registration.value().limits.minimum_instruction_bytes) {
                std::lock_guard<std::mutex> lock(impl_->undecodable_mutex);
                impl_->undecodable_rvas.push_back(current);
                break;
            }
            if (use_x86_tile_decoder) {
                const auto tile_bytes = std::min({mapping->available_bytes,
                    impl_->settings.decode_read_window_bytes,
                    decode::x86_tile_decode_limits_t::hard_maximum_window_bytes,
                    decode::x86_tile_decode_limits_t::hard_maximum_instructions});
                if (tile_bytes == 0) {
                    std::lock_guard<std::mutex> lock(impl_->undecodable_mutex);
                    impl_->undecodable_rvas.push_back(current);
                    break;
                }
                decode::x86_tile_decode_request_t tile_request;
                tile_request.start_address = rva_address(*impl_->image, current);
                tile_request.provider_offset = mapping->provider_offset;
                tile_request.byte_count = tile_bytes;
                tile_request.image_base = impl_->image->image_base;
                tile_request.image_size = impl_->image->image_size;
                tile_request.provenance = work.provenance;
                tile_request.confidence = work.confidence;
                tile_request.stable_source_id = stable_mix(work.stable_source_id, current);
                tile_request.limits.maximum_window_bytes = tile_bytes;
                tile_request.limits.maximum_decode_attempts = tile_bytes;
                tile_request.limits.maximum_instructions = tile_bytes;
                tile_request.limits.maximum_operand_facts = tile_bytes * 10ULL;
                tile_request.limits.maximum_target_facts = tile_bytes * 11ULL;
                tile_request.limits.maximum_invalid_bytes = tile_bytes;
                tile_request.limits.maximum_coverage_spans = tile_bytes;
                auto tile = x86_tile_decoder->decode_tile(*x86_tile_snapshot, tile_request,
                    impl_->cancellation.token());
                if (!tile) {
                    finish();
                    return workspace_result_t<void>::failure(tile.error());
                }
                requested += tile.value().usage.snapshot_window_bytes;
                tile_input_bytes += tile.value().usage.input_bytes;
                tile_decoded_bytes += tile.value().usage.decoded_bytes;
                tile_instructions += tile.value().usage.instructions;
                std::uint64_t tile_end = 0;
                if (!checked_add_u64(current, tile_bytes, tile_end)) {
                    finish();
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::range_overflow,
                        "x86 tile decode range overflowed", "decode"));
                }
                bool tile_stopped = false;
                for (std::size_t index = 0; index < tile.value().instructions.size(); ++index) {
                    if (index != 0) {
                        if (++checks >= impl_->settings.cancellation_check_interval) {
                            checks = 0;
                            active = impl_->ensure_active(runtime_cancel, "decode");
                            if (!active) {
                                finish();
                                return active;
                            }
                        }
                        if (++trace > impl_->settings.max_trace_instructions) {
                            auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                "recursive decode trace exceeds analysis budget", "decode");
                            {
                                std::lock_guard<std::mutex> lock(impl_->decode_mutex);
                                impl_->decode_error = error;
                                impl_->decode_stop = true;
                            }
                            tile_stopped = true;
                            break;
                        }
                    }
                    if (!executable_rva(*impl_->image, current)) {
                        tile_stopped = true;
                        break;
                    }
                    if (index != 0) {
                        std::lock_guard<std::mutex> lock(impl_->decode_mutex);
                        const auto claimed = impl_->claimed.find(current);
                        if (claimed != impl_->claimed.end() &&
                            !stronger_decode_work(work, claimed->second)) {
                            tile_stopped = true;
                            break;
                        }
                        if (impl_->claimed.size() >= impl_->settings.max_decoded_instructions ||
                            !impl_->reserve_decode_storage(sizeof(decode_work_t) * 2ULL)) {
                            impl_->decode_error = make_workspace_error(
                                workspace_error_code_t::limit_exceeded,
                                "decode claim storage exceeds analysis budget", "decode");
                            impl_->decode_stop = true;
                            tile_stopped = true;
                            break;
                        }
                        impl_->claimed[current] = work;
                    }
                    const auto& instruction = tile.value().instructions[index];
                    if (instruction.address != rva_address(*impl_->image, current)) {
                        std::lock_guard<std::mutex> lock(impl_->undecodable_mutex);
                        impl_->undecodable_rvas.push_back(current);
                        tile_stopped = true;
                        break;
                    }
                    const auto operand_end = static_cast<std::uint64_t>(
                        instruction.operand_fact_begin) + instruction.operand_fact_count;
                    const auto target_end = static_cast<std::uint64_t>(
                        instruction.target_fact_begin) + instruction.target_fact_count;
                    if (operand_end > tile.value().operand_facts.size() ||
                        target_end > tile.value().target_facts.size() ||
                        instruction.operand_fact_count > decoded.operands.size() ||
                        instruction.target_fact_count > decoded.targets.size()) {
                        finish();
                        return workspace_result_t<void>::failure(make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            "x86 tile decoder returned invalid Compact IR ranges", "decode"));
                    }
                    decoded = {};
                    decoded.instruction = instruction;
                    decoded.instruction.provenance = work.provenance;
                    decoded.instruction.confidence = work.confidence;
                    decoded.instruction.stable_source_id = stable_mix(work.stable_source_id,
                        current);
                    decoded.operand_count = instruction.operand_fact_count;
                    decoded.target_count = instruction.target_fact_count;
                    std::copy_n(tile.value().operand_facts.begin() + instruction.operand_fact_begin,
                        decoded.operand_count, decoded.operands.begin());
                    std::copy_n(tile.value().target_facts.begin() + instruction.target_fact_begin,
                        decoded.target_count, decoded.targets.begin());
                    arch_decode_request_t request;
                    request.address = decoded.instruction.address;
                    if (!checked_add_u64(mapping->provider_offset,
                            current - tile_request.start_address.value, request.provider_offset)) {
                        finish();
                        return workspace_result_t<void>::failure(make_workspace_error(
                            workspace_error_code_t::range_overflow,
                            "x86 tile provider offset overflowed", "decode"));
                    }
                    request.image_base = impl_->image->image_base;
                    request.image_size = impl_->image->image_size;
                    request.available_bytes = decoded.instruction.length;
                    request.provenance = work.provenance;
                    request.confidence = work.confidence;
                    request.stable_source_id = decoded.instruction.stable_source_id;
                    if (!accept_decoded(decoded, *mapping, request)) {
                        tile_stopped = true;
                        break;
                    }
                }
                if (!tile_stopped && current < tile_end) {
                    std::lock_guard<std::mutex> lock(impl_->undecodable_mutex);
                    impl_->undecodable_rvas.push_back(current);
                    tile_stopped = true;
                }
                if (tile_stopped)
                    break;
                continue;
            }
            const auto available = std::min<std::uint64_t>(mapping->available_bytes,
                std::min<std::uint64_t>(impl_->settings.decode_read_window_bytes,
                    decoder->registration().limits.maximum_instruction_bytes));
            if (available == 0 || available > std::numeric_limits<std::uint16_t>::max())
                break;
            auto lease = impl_->workspace->provider().lease(mapping->provider_offset, available,
                impl_->cancellation.token());
            if (!lease) {
                finish();
                return workspace_result_t<void>::failure(lease.error());
            }
            requested += available;
            arch_decode_request_t request;
            request.address = rva_address(*impl_->image, current);
            request.provider_offset = mapping->provider_offset;
            request.runtime_address = impl_->image->image_base + current;
            request.image_base = impl_->image->image_base;
            request.image_size = impl_->image->image_size;
            request.available_bytes = static_cast<std::uint16_t>(available);
            request.provenance = work.provenance;
            request.confidence = work.confidence;
            request.stable_source_id = stable_mix(work.stable_source_id, current);
            auto decoded_result = decoder->decode_one(lease.value(), mapping->provider_offset,
                request, decoded);
            if (!decoded_result) {
                if (decoded_result.error().code != workspace_error_code_t::decode_failure) {
                    finish();
                    return workspace_result_t<void>::failure(decoded_result.error());
                }
                std::lock_guard<std::mutex> lock(impl_->undecodable_mutex);
                impl_->undecodable_rvas.push_back(current);
                break;
            }
            if (!accept_decoded(decoded, *mapping, request))
                break;
        }
        finish();
        if (const auto error = impl_->current_decode_error())
            return workspace_result_t<void>::failure(*error);
    }
    const auto input_bytes = use_x86_tile_decoder ? tile_input_bytes : decoder->usage().input_bytes;
    const auto decoded_bytes = use_x86_tile_decoder ? tile_decoded_bytes : decoder->usage().decoded_bytes;
    const auto instruction_count = use_x86_tile_decoder
        ? tile_instructions : decoder->usage().instructions;
    const auto cancellation_polls = use_x86_tile_decoder ? checks : decoder->usage().cancellation_polls;
    impl_->metrics->add(analysis_metric_t::read_bytes, input_bytes);
    impl_->metrics->add(analysis_metric_t::mapped_bytes, requested);
    impl_->metrics->end_phase(measurement, input_bytes, decoded_bytes,
        instruction_count, cancellation_polls, false);
    return workspace_result_t<void>::success();
}

workspace_result_t<void> pe_baseline_analyzer_t::decode_merge_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::decode);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto active = impl_->ensure_active(runtime_cancel, "decode_merge");
    if (!active)
        return active;
    std::vector<decoded_candidate_t> candidates;
    std::uint64_t candidate_count = 0;
    for (const auto& lane : impl_->lane_outputs) {
        std::uint64_t updated_count = 0;
        if (!checked_add_u64(candidate_count, lane.candidates.size(), updated_count) ||
            updated_count > impl_->settings.max_decoded_instructions) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "decode candidate count exceeds analysis budget", "decode_merge"));
        }
        candidate_count = updated_count;
    }
    std::uint64_t candidate_bytes = 0;
    if (!checked_mul_u64(candidate_count, sizeof(decoded_candidate_t), candidate_bytes) ||
        candidate_bytes > impl_->settings.max_analysis_memory_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "decode merge candidate storage exceeds analysis memory budget", "decode_merge"));
    }
    candidates.reserve(static_cast<std::size_t>(candidate_count));
    for (auto& lane : impl_->lane_outputs) {
        candidates.insert(candidates.end(), std::make_move_iterator(lane.candidates.begin()),
            std::make_move_iterator(lane.candidates.end()));
        lane.candidates.clear();
    }
    std::sort(candidates.begin(), candidates.end(), [](const decoded_candidate_t& lhs,
        const decoded_candidate_t& rhs) {
        if (lhs.rva != rhs.rva)
            return lhs.rva < rhs.rva;
        const auto lhs_rank = provenance_rank(lhs.instruction.provenance);
        const auto rhs_rank = provenance_rank(rhs.instruction.provenance);
        if (lhs_rank != rhs_rank)
            return lhs_rank > rhs_rank;
        if (lhs.instruction.confidence != rhs.instruction.confidence)
            return lhs.instruction.confidence > rhs.instruction.confidence;
        if (lhs.instruction.length != rhs.instruction.length)
            return lhs.instruction.length < rhs.instruction.length;
        if (lhs.instruction.opcode_id != rhs.instruction.opcode_id)
            return lhs.instruction.opcode_id < rhs.instruction.opcode_id;
        return lhs.instruction.stable_source_id < rhs.instruction.stable_source_id;
    });
    std::vector<std::uint64_t> conflicts;
    std::vector<decoded_candidate_t> accepted;
    accepted.reserve(candidates.size());
    for (auto& candidate : candidates) {
        if (runtime_cancel.load(std::memory_order_acquire))
            return impl_->ensure_active(runtime_cancel, "decode_merge");
        if (!accepted.empty() && candidate.rva < accepted.back().end_rva) {
            if (candidate.rva != accepted.back().rva || candidate.end_rva != accepted.back().end_rva ||
                candidate.instruction.opcode_id != accepted.back().instruction.opcode_id) {
                conflicts.push_back(accepted.back().rva);
                conflicts.push_back(candidate.rva);
            }
            continue;
        }
        accepted.push_back(std::move(candidate));
    }
    impl_->draft->instructions.clear();
    impl_->draft->operand_facts.clear();
    impl_->draft->target_facts.clear();
    impl_->draft->instructions.reserve(accepted.size());
    for (std::size_t index = 0; index < accepted.size(); ++index) {
        auto& candidate = accepted[index];
        const auto* source = candidate.source_lane < impl_->lane_outputs.size()
            ? &impl_->lane_outputs[candidate.source_lane] : nullptr;
        if (!source) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "decode candidate references an invalid lane", "decode_merge"));
        }
        const auto operand_end = static_cast<std::uint64_t>(candidate.instruction.operand_fact_begin) +
            candidate.instruction.operand_fact_count;
        const auto target_end = static_cast<std::uint64_t>(candidate.instruction.target_fact_begin) +
            candidate.instruction.target_fact_count;
        if (operand_end > source->operands.size() || target_end > source->targets.size()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "decode candidate fact range is invalid", "decode_merge"));
        }
        auto instruction = candidate.instruction;
        instruction.id = kInstructionEntityTag | static_cast<std::uint64_t>(index + 1);
        instruction.operand_fact_begin = static_cast<std::uint32_t>(impl_->draft->operand_facts.size());
        instruction.target_fact_begin = static_cast<std::uint32_t>(impl_->draft->target_facts.size());
        for (std::uint64_t operand = candidate.instruction.operand_fact_begin;
             operand < operand_end; ++operand) {
            auto value = source->operands[static_cast<std::size_t>(operand)];
            value.instruction_id = instruction.id;
            impl_->draft->operand_facts.push_back(std::move(value));
        }
        for (std::uint64_t target = candidate.instruction.target_fact_begin;
             target < target_end; ++target) {
            auto value = source->targets[static_cast<std::size_t>(target)];
            value.instruction_id = instruction.id;
            impl_->draft->target_facts.push_back(std::move(value));
        }
        impl_->draft->instructions.push_back(std::move(instruction));
    }
    for (auto& lane : impl_->lane_outputs) {
        lane.operands.clear();
        lane.targets.clear();
    }
    std::sort(conflicts.begin(), conflicts.end());
    conflicts.erase(std::unique(conflicts.begin(), conflicts.end()), conflicts.end());
    std::vector<std::uint64_t> undecodable;
    {
        std::lock_guard<std::mutex> lock(impl_->undecodable_mutex);
        undecodable = std::move(impl_->undecodable_rvas);
    }
    std::sort(undecodable.begin(), undecodable.end());
    undecodable.erase(std::unique(undecodable.begin(), undecodable.end()), undecodable.end());
    const auto is_padding = [&](std::uint64_t start, std::uint64_t end)
        -> workspace_result_t<std::optional<bool>> {
        if (end <= start)
            return workspace_result_t<std::optional<bool>>::success(false);
        std::uint64_t cursor = start;
        while (cursor < end) {
            const auto mapping = file_mapping(*impl_->image, cursor);
            if (!mapping)
                return workspace_result_t<std::optional<bool>>::success(std::nullopt);
            const auto bytes = std::min(end - cursor, mapping->available_bytes);
            if (bytes == 0)
                return workspace_result_t<std::optional<bool>>::success(std::nullopt);
            auto lease = impl_->workspace->provider().lease(mapping->provider_offset, bytes,
                impl_->cancellation.token());
            if (!lease)
                return workspace_result_t<std::optional<bool>>::failure(lease.error());
            if (!std::all_of(lease.value().begin(), lease.value().end(), padding_byte))
                return workspace_result_t<std::optional<bool>>::success(false);
            cursor += bytes;
        }
        return workspace_result_t<std::optional<bool>>::success(true);
    };
    impl_->draft->coverage.clear();
    std::size_t instruction_index = 0;
    for (const auto& range : executable_ranges(*impl_->image)) {
        std::uint64_t cursor = range.start;
        while (instruction_index < impl_->draft->instructions.size() &&
            impl_->draft->instructions[instruction_index].address.value < range.start)
            ++instruction_index;
        const auto append_gap = [&](std::uint64_t start, std::uint64_t end)
            -> workspace_result_t<void> {
            auto padding = is_padding(start, end);
            if (!padding)
                return workspace_result_t<void>::failure(padding.error());
            coverage_span_t span;
            span.start = rva_address(*impl_->image, start);
            span.size = end - start;
            const auto failed = std::lower_bound(undecodable.begin(), undecodable.end(), start);
            const bool decode_failed = failed != undecodable.end() && *failed < end;
            if (!padding.value()) {
                span.reason = coverage_reason_t::proven_data;
                span.provenance = fact_provenance_t::linear_validation;
                span.confidence = 100;
                span.detail_code = 3;
            } else if (*padding.value()) {
                span.reason = coverage_reason_t::padding;
                span.provenance = fact_provenance_t::linear_validation;
                span.confidence = 100;
                span.detail_code = 1;
            } else {
                span.reason = coverage_reason_t::undecodable;
                span.provenance = fact_provenance_t::gap_recovery;
                span.confidence = 25;
                span.detail_code = decode_failed ? 5 : 2;
            }
            if (!append_coverage(impl_->draft->coverage, std::move(span),
                    impl_->settings.max_coverage_spans)) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "coverage span count exceeds analysis budget", "decode_merge"));
            }
            return workspace_result_t<void>::success();
        };
        auto local = instruction_index;
        while (local < impl_->draft->instructions.size()) {
            const auto& instruction = impl_->draft->instructions[local];
            if (instruction.address.value >= range.end)
                break;
            if (instruction.address.value < cursor ||
                instruction.address.value + instruction.length > range.end) {
                ++local;
                continue;
            }
            if (instruction.address.value > cursor) {
                auto gap = append_gap(cursor, instruction.address.value);
                if (!gap)
                    return gap;
            }
            coverage_span_t span;
            span.start = instruction.address;
            span.size = instruction.length;
            const bool conflict = std::binary_search(conflicts.begin(), conflicts.end(),
                instruction.address.value);
            span.reason = conflict ? coverage_reason_t::conflict : coverage_reason_t::decoded;
            span.provenance = instruction.provenance;
            span.confidence = instruction.confidence;
            span.detail_code = conflict ? 4 : 0;
            if (!append_coverage(impl_->draft->coverage, std::move(span),
                    impl_->settings.max_coverage_spans)) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "coverage span count exceeds analysis budget", "decode_merge"));
            }
            cursor = instruction.address.value + instruction.length;
            ++local;
        }
        if (cursor < range.end) {
            auto gap = append_gap(cursor, range.end);
            if (!gap)
                return gap;
        }
        instruction_index = local;
    }
    impl_->metrics->set(analysis_metric_t::instructions, impl_->draft->instructions.size());
    for (const auto& span : impl_->draft->coverage) {
        const auto metric = span.reason == coverage_reason_t::decoded ? analysis_metric_t::coverage_decoded_bytes :
            span.reason == coverage_reason_t::proven_data ? analysis_metric_t::coverage_data_bytes :
            span.reason == coverage_reason_t::padding ? analysis_metric_t::coverage_padding_bytes :
            span.reason == coverage_reason_t::conflict ? analysis_metric_t::coverage_conflict_bytes :
            analysis_metric_t::coverage_undecodable_bytes;
        impl_->metrics->add(metric, span.size);
    }
    impl_->decode_candidate_count.store(0, std::memory_order_release);
    impl_->decode_storage_bytes.store(0, std::memory_order_release);
    impl_->metrics->end_phase(measurement, 0, impl_->draft->instructions.size() * sizeof(instruction_record_t),
        impl_->draft->instructions.size(), 1, false);
    return impl_->update_progress("decode", impl_->draft->instructions.size(),
        impl_->draft->instructions.size(), impl_->metrics->snapshot().value(analysis_metric_t::decoded_bytes),
        impl_->executable_bytes());
}

workspace_result_t<void> pe_baseline_analyzer_t::blocks_phase(const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::blocks);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto active = impl_->ensure_active(runtime_cancel, "blocks");
    if (!active)
        return active;
    auto current = snapshot_memory_bytes(*impl_->draft);
    if (!current || current.value() >= impl_->settings.max_analysis_memory_bytes) {
        return workspace_result_t<void>::failure(current ? make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "function recovery has no remaining memory budget", "blocks") : current.error());
    }
    impl_->effective_function_limits = impl_->settings.function_limits;
    impl_->effective_function_limits.max_result_bytes = std::min(
        impl_->effective_function_limits.max_result_bytes,
        impl_->settings.max_analysis_memory_bytes - current.value());
    auto built = function_recovery_t::build_blocks(*impl_->image, impl_->draft->instructions,
        impl_->draft->target_facts, impl_->seeds, impl_->effective_function_limits,
        impl_->cancellation.token());
    if (!built)
        return workspace_result_t<void>::failure(built.error());
    impl_->block_result = built.take_value();
    impl_->metrics->set(analysis_metric_t::blocks, impl_->block_result.blocks.size());
    impl_->metrics->end_phase(measurement, impl_->draft->instructions.size() * sizeof(instruction_record_t),
        impl_->block_result.blocks.size() * sizeof(basic_block_record_t), impl_->block_result.blocks.size(), 1, false);
    return impl_->update_progress("blocks", impl_->block_result.blocks.size(),
        impl_->block_result.blocks.size(), 0, impl_->executable_bytes());
}

workspace_result_t<void> pe_baseline_analyzer_t::functions_phase(const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::functions);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto active = impl_->ensure_active(runtime_cancel, "functions");
    if (!active)
        return active;
    auto recovered = function_recovery_t::recover_functions(*impl_->image, impl_->draft->instructions,
        impl_->seeds, std::move(impl_->block_result), impl_->effective_function_limits,
        impl_->cancellation.token());
    if (!recovered)
        return workspace_result_t<void>::failure(recovered.error());
    impl_->function_result = recovered.take_value();
    impl_->metrics->set(analysis_metric_t::functions, impl_->function_result.functions.size());
    impl_->metrics->set(analysis_metric_t::thunks, static_cast<std::uint64_t>(std::count_if(
        impl_->function_result.functions.begin(), impl_->function_result.functions.end(),
        [](const function_record_t& function) { return function.thunk; })));
    impl_->metrics->set(analysis_metric_t::noreturn_functions, static_cast<std::uint64_t>(std::count_if(
        impl_->function_result.functions.begin(), impl_->function_result.functions.end(),
        [](const function_record_t& function) { return function.noreturn; })));
    impl_->metrics->end_phase(measurement, impl_->seeds.size() * sizeof(function_seed_t),
        impl_->function_result.functions.size() * sizeof(function_record_t),
        impl_->function_result.functions.size(), 1, false);
    return impl_->update_progress("functions", impl_->function_result.functions.size(),
        impl_->function_result.functions.size(), 0, impl_->executable_bytes());
}

workspace_result_t<void> pe_baseline_analyzer_t::cfg_calls_phase(const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::cfg_calls);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto active = impl_->ensure_active(runtime_cancel, "cfg_calls");
    if (!active)
        return active;
    auto finalized = function_recovery_t::finalize_cfg_calls(*impl_->image,
        impl_->workspace->provider(), impl_->draft->instructions, impl_->draft->operand_facts,
        impl_->draft->target_facts, std::move(impl_->function_result),
        impl_->effective_function_limits, impl_->cancellation.token());
    if (!finalized)
        return workspace_result_t<void>::failure(finalized.error());
    impl_->function_result = finalized.take_value();
    impl_->draft->blocks = std::move(impl_->function_result.blocks);
    impl_->draft->functions = std::move(impl_->function_result.functions);
    impl_->draft->function_chunks = std::move(impl_->function_result.function_chunks);
    impl_->draft->function_block_memberships = std::move(impl_->function_result.function_block_memberships);
    impl_->draft->edges = std::move(impl_->function_result.edges);
    impl_->metrics->set(analysis_metric_t::cfg_edges, static_cast<std::uint64_t>(std::count_if(
        impl_->draft->edges.begin(), impl_->draft->edges.end(), [](const edge_record_t& edge) {
            return edge.kind != edge_kind_t::call && edge.kind != edge_kind_t::tail_call;
        })));
    impl_->metrics->set(analysis_metric_t::call_edges, static_cast<std::uint64_t>(std::count_if(
        impl_->draft->edges.begin(), impl_->draft->edges.end(), [](const edge_record_t& edge) {
            return edge.kind == edge_kind_t::call || edge.kind == edge_kind_t::tail_call;
        })));
    impl_->metrics->set(analysis_metric_t::switches, impl_->function_result.switches.size());
    impl_->metrics->end_phase(measurement, impl_->draft->instructions.size() * sizeof(instruction_record_t),
        impl_->draft->edges.size() * sizeof(edge_record_t), impl_->draft->edges.size(), 1, false);
    return impl_->update_progress("cfg_calls", impl_->draft->edges.size(), impl_->draft->edges.size(),
        0, impl_->executable_bytes());
}

workspace_result_t<void> pe_baseline_analyzer_t::xrefs_phase(const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::xrefs);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto active = impl_->ensure_active(runtime_cancel, "xrefs");
    if (!active)
        return active;
    auto current = snapshot_memory_bytes(*impl_->draft);
    if (!current || current.value() >= impl_->settings.max_analysis_memory_bytes) {
        return workspace_result_t<void>::failure(current ? make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "xref analysis has no remaining memory budget", "xrefs") : current.error());
    }
    auto limits = impl_->settings.xref_limits;
    limits.max_result_bytes = std::min(limits.max_result_bytes,
        impl_->settings.max_analysis_memory_bytes - current.value());
    auto built = xref_builder_t::build(*impl_->image, impl_->workspace->provider(),
        impl_->draft->instructions, impl_->draft->operand_facts, impl_->draft->target_facts,
        limits, impl_->cancellation.token());
    if (!built)
        return workspace_result_t<void>::failure(built.error());
    impl_->xref_result = built.take_value();
    impl_->draft->xrefs = std::move(impl_->xref_result.xrefs);
    impl_->metrics->set(analysis_metric_t::xrefs, impl_->draft->xrefs.size());
    impl_->metrics->set(analysis_metric_t::data_candidates, impl_->xref_result.data_candidates.size());
    impl_->metrics->add(analysis_metric_t::provider_leases, impl_->xref_result.provider_leases);
    impl_->metrics->add(analysis_metric_t::mapped_bytes, impl_->xref_result.mapped_bytes);
    impl_->metrics->add(analysis_metric_t::read_bytes, impl_->xref_result.bytes_scanned);
    impl_->metrics->end_phase(measurement, impl_->xref_result.bytes_scanned,
        impl_->draft->xrefs.size() * sizeof(xref_record_t), impl_->draft->xrefs.size(), 1, false);
    return impl_->update_progress("xrefs", impl_->draft->xrefs.size(), impl_->draft->xrefs.size(),
        impl_->xref_result.bytes_scanned, impl_->xref_result.bytes_scanned);
}

workspace_result_t<void> pe_baseline_analyzer_t::strings_data_phase(const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::strings_data);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto active = impl_->ensure_active(runtime_cancel, "strings_data");
    if (!active)
        return active;
    std::vector<string_record_t> strings;
    auto base_memory = snapshot_memory_bytes(*impl_->draft);
    if (!base_memory)
        return workspace_result_t<void>::failure(base_memory.error());
    std::uint64_t string_storage = base_memory.value();
    std::uint64_t scanned = 0;
    std::uint64_t leases = 0;
    const auto add_string = [&](std::uint64_t rva, std::uint64_t bytes, string_encoding_t encoding,
        std::string value, std::uint8_t confidence) -> workspace_result_t<void> {
        if (value.size() < impl_->settings.minimum_string_length)
            return workspace_result_t<void>::success();
        if (value.size() > impl_->settings.max_string_value_bytes ||
            strings.size() >= impl_->settings.max_strings) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded, "string analysis exceeds its budget", "strings_data"));
        }
        std::uint64_t record_bytes = 0;
        std::uint64_t updated_storage = 0;
        if (!checked_add_u64(sizeof(string_record_t), value.capacity(), record_bytes) ||
            !checked_add_u64(string_storage, record_bytes, updated_storage) ||
            updated_storage > impl_->settings.max_analysis_memory_bytes) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "string storage exceeds analysis memory budget", "strings_data"));
        }
        string_storage = updated_storage;
        string_record_t record;
        record.address = rva_address(*impl_->image, rva);
        record.byte_length = bytes;
        record.encoding = encoding;
        record.value = std::move(value);
        record.provenance = fact_provenance_t::linear_validation;
        record.confidence = confidence;
        strings.push_back(std::move(record));
        return workspace_result_t<void>::success();
    };
    const auto scan_region = [&](const image_range_t& range) -> workspace_result_t<void> {
        if ((range.permissions & image_permission_read) == 0)
            return workspace_result_t<void>::success();
        std::uint64_t cursor = range.start;
        std::string ascii;
        std::uint64_t ascii_start = 0;
        while (cursor < range.end) {
            active = impl_->ensure_active(runtime_cancel, "strings_data");
            if (!active)
                return active;
            const auto mapping = file_mapping(*impl_->image, cursor);
            if (!mapping)
                break;
            const auto bytes = std::min({range.end - cursor, mapping->available_bytes,
                impl_->settings.string_read_window_bytes});
            if (bytes == 0)
                break;
            if (scanned > impl_->settings.max_string_scan_bytes - bytes) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "string scan byte budget exceeded", "strings_data"));
            }
            auto lease = impl_->workspace->provider().lease(mapping->provider_offset, bytes,
                impl_->cancellation.token());
            if (!lease)
                return workspace_result_t<void>::failure(lease.error());
            ++leases;
            scanned += bytes;
            if (!impl_->settings.scan_utf8) {
                cursor += bytes;
                continue;
            }
            for (std::uint64_t index = 0; index < bytes; ++index) {
                const auto value = lease.value().data()[static_cast<std::size_t>(index)];
                if (value >= 0x20 && value <= 0x7e) {
                    if (ascii.empty())
                        ascii_start = cursor + index;
                    if (ascii.size() < impl_->settings.max_string_value_bytes)
                        ascii.push_back(static_cast<char>(value));
                    continue;
                }
                auto added = add_string(ascii_start, ascii.size(), string_encoding_t::ascii,
                    std::move(ascii), 95);
                if (!added)
                    return added;
                ascii.clear();
            }
            cursor += bytes;
        }
        auto added = add_string(ascii_start, ascii.size(), string_encoding_t::ascii,
            std::move(ascii), 95);
        if (!added)
            return added;
        return workspace_result_t<void>::success();
    };
    for (const auto& range : image_ranges(*impl_->image)) {
        auto scanned_region = scan_region(range);
        if (!scanned_region)
            return scanned_region;
    }
    std::sort(strings.begin(), strings.end(), [](const string_record_t& lhs, const string_record_t& rhs) {
        if (lhs.address != rhs.address)
            return lhs.address < rhs.address;
        if (lhs.encoding != rhs.encoding)
            return lhs.encoding < rhs.encoding;
        return lhs.value < rhs.value;
    });
    strings.erase(std::unique(strings.begin(), strings.end(), [](const string_record_t& lhs,
        const string_record_t& rhs) {
        return lhs.address == rhs.address && lhs.encoding == rhs.encoding && lhs.value == rhs.value;
    }), strings.end());
    for (std::size_t index = 0; index < strings.size(); ++index)
        strings[index].id = kStringEntityTag | static_cast<std::uint64_t>(index + 1);
    impl_->draft->strings = std::move(strings);
    impl_->metrics->set(analysis_metric_t::strings, impl_->draft->strings.size());
    impl_->metrics->add(analysis_metric_t::provider_leases, leases);
    impl_->metrics->add(analysis_metric_t::mapped_bytes, scanned);
    impl_->metrics->add(analysis_metric_t::read_bytes, scanned);
    impl_->metrics->end_phase(measurement, scanned, impl_->draft->strings.size() * sizeof(string_record_t),
        impl_->draft->strings.size(), 1, false);
    return impl_->update_progress("strings_data", impl_->draft->strings.size(),
        impl_->draft->strings.size(), scanned, scanned);
}

workspace_result_t<void> pe_baseline_analyzer_t::metadata_symbols_types_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::metadata_symbols_types);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto active = impl_->ensure_active(runtime_cancel, "metadata_symbols_types");
    if (!active)
        return active;
    std::vector<symbol_record_t> symbols;
    std::vector<type_candidate_record_t> types;
    const auto add_symbol = [&symbols](address_t address, std::string name, symbol_kind_t kind,
        fact_provenance_t provenance, std::uint8_t confidence) {
        if (name.empty())
            return;
        symbol_record_t value;
        value.address = address;
        value.name = std::move(name);
        value.kind = kind;
        value.provenance = provenance;
        value.confidence = confidence;
        symbols.push_back(std::move(value));
    };
    for (const auto& imported : impl_->image->imports) {
        std::string name = imported.library;
        name.push_back('!');
        name += imported.name.value_or("#" + std::to_string(imported.ordinal.value_or(0)));
        add_symbol(imported.address, std::move(name), symbol_kind_t::import_symbol,
            fact_provenance_t::relocation, 100);
    }
    for (const auto& exported : impl_->image->exports) {
        if (!exported.name)
            continue;
        add_symbol(exported.address, *exported.name,
            executable_rva(*impl_->image, to_rva(*impl_->image, exported.address).value_or(
                impl_->image->image_size)) ? symbol_kind_t::function : symbol_kind_t::export_symbol,
            fact_provenance_t::export_entry, 100);
    }
    for (const auto& image_symbol : impl_->image->symbols) {
        const auto kind = image_symbol.kind == image_symbol_kind_t::function ? symbol_kind_t::function :
            image_symbol.kind == image_symbol_kind_t::debug_symbol ? symbol_kind_t::debug_symbol :
            image_symbol.kind == image_symbol_kind_t::import_symbol ? symbol_kind_t::import_symbol :
            symbol_kind_t::data;
        add_symbol(image_symbol.address, image_symbol.name, kind,
            kind == symbol_kind_t::debug_symbol ? fact_provenance_t::debug_symbol :
            kind == symbol_kind_t::function ? fact_provenance_t::export_entry : fact_provenance_t::relocation,
            image_symbol.defined ? 90 : 70);
    }
    for (const auto& function : impl_->draft->functions) {
        const auto name = "sub_" + hex_rva(function.start.value);
        add_symbol(function.start, name, symbol_kind_t::function, function.provenance, function.confidence);
        type_candidate_record_t type;
        type.address = function.start;
        type.kind = type_candidate_kind_t::function_prototype;
        type.display_name = name;
        type.canonical_type = "unknown_function";
        type.provenance = function.provenance;
        type.confidence = function.confidence;
        types.push_back(std::move(type));
    }
    for (const auto& data : impl_->xref_result.data_candidates) {
        type_candidate_record_t type;
        type.address = data.address;
        type.kind = data.target ? type_candidate_kind_t::pointer_object : type_candidate_kind_t::global_object;
        type.display_name = "data_" + hex_rva(data.address.value);
        type.canonical_type = data.target ? "unknown_pointer" : "unknown_data";
        type.provenance = data.provenance;
        type.confidence = data.confidence;
        types.push_back(std::move(type));
    }
    std::sort(symbols.begin(), symbols.end(), [](const symbol_record_t& lhs, const symbol_record_t& rhs) {
        if (lhs.address != rhs.address)
            return lhs.address < rhs.address;
        if (lhs.name != rhs.name)
            return lhs.name < rhs.name;
        return lhs.kind < rhs.kind;
    });
    symbols.erase(std::unique(symbols.begin(), symbols.end(), [](const symbol_record_t& lhs,
        const symbol_record_t& rhs) {
        return lhs.address == rhs.address && lhs.name == rhs.name && lhs.kind == rhs.kind;
    }), symbols.end());
    for (std::size_t index = 0; index < symbols.size(); ++index)
        symbols[index].id = kSymbolEntityTag | static_cast<std::uint64_t>(index + 1);
    for (auto& function : impl_->draft->functions) {
        const auto found = std::find_if(symbols.begin(), symbols.end(), [&function](const symbol_record_t& symbol) {
            return symbol.address == function.start && symbol.kind == symbol_kind_t::function;
        });
        if (found != symbols.end())
            function.symbol_id = found->id;
    }
    std::sort(types.begin(), types.end(), [](const type_candidate_record_t& lhs,
        const type_candidate_record_t& rhs) {
        if (lhs.address != rhs.address)
            return lhs.address < rhs.address;
        if (lhs.kind != rhs.kind)
            return lhs.kind < rhs.kind;
        return lhs.display_name < rhs.display_name;
    });
    types.erase(std::unique(types.begin(), types.end(), [](const type_candidate_record_t& lhs,
        const type_candidate_record_t& rhs) {
        return lhs.address == rhs.address && lhs.kind == rhs.kind && lhs.display_name == rhs.display_name;
    }), types.end());
    for (std::size_t index = 0; index < types.size(); ++index)
        types[index].id = kTypeEntityTag | static_cast<std::uint64_t>(index + 1);
    impl_->draft->symbols = std::move(symbols);
    impl_->type_candidates = std::move(types);
    impl_->metrics->set(analysis_metric_t::symbols, impl_->draft->symbols.size());
    impl_->metrics->set(analysis_metric_t::types, impl_->type_candidates.size());
    impl_->metrics->end_phase(measurement, impl_->image->symbols.size() + impl_->image->imports.size() +
        impl_->image->exports.size(), impl_->draft->symbols.size() * sizeof(symbol_record_t),
        impl_->draft->symbols.size() + impl_->type_candidates.size(), 1, false);
    return impl_->update_progress("metadata_symbols_types", impl_->draft->symbols.size() +
        impl_->type_candidates.size(), impl_->draft->symbols.size() + impl_->type_candidates.size(),
        0, impl_->executable_bytes());
}

workspace_result_t<void> pe_baseline_analyzer_t::search_index_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::search_index);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto active = impl_->ensure_active(runtime_cancel, "search_index");
    if (!active)
        return active;
    impl_->draft->baseline_complete = true;
    auto coverage = validate_coverage_linear_cancellable(*impl_->draft, impl_->cancellation.token());
    if (!coverage)
        return coverage;
    auto validated = validate_analysis_snapshot(*impl_->draft, false, impl_->cancellation.token());
    if (!validated)
        return validated;
    impl_->final_snapshot = impl_->draft;
    impl_->draft.reset();
    auto bytes = snapshot_memory_bytes(*impl_->final_snapshot);
    if (!bytes || bytes.value() >= impl_->settings.max_analysis_memory_bytes) {
        return workspace_result_t<void>::failure(bytes ? make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "analysis snapshot exhausts the retained memory budget", "search_index") : bytes.error());
    }
    auto limits = impl_->settings.search_limits;
    limits.max_index_bytes = std::min(limits.max_index_bytes,
        impl_->settings.max_analysis_memory_bytes - bytes.value());
    auto index = search_index_t::build(impl_->final_snapshot,
        std::move(impl_->xref_result.data_candidates), std::move(impl_->function_result.switches),
        std::move(impl_->type_candidates), impl_->metrics, limits, impl_->cancellation.token());
    if (!index)
        return workspace_result_t<void>::failure(index.error());
    impl_->search = index.take_value();
    std::uint64_t retained = 0;
    if (!checked_add_u64(bytes.value(), impl_->search->memory_bytes(), retained) ||
        retained > impl_->settings.max_analysis_memory_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "retained baseline state exceeds analysis memory budget", "search_index"));
    }
    const auto count = impl_->final_snapshot->instructions.size() + impl_->final_snapshot->symbols.size() +
        impl_->final_snapshot->strings.size() + impl_->search->data_candidates().size() +
        impl_->search->switches().size() + impl_->search->types().size();
    impl_->metrics->end_phase(measurement, count, retained, count, 1, false);
    return impl_->update_progress("search_index", count, count,
        impl_->metrics->snapshot().value(analysis_metric_t::indexed_bytes),
        impl_->metrics->snapshot().value(analysis_metric_t::indexed_bytes));
}

workspace_result_t<void> pe_baseline_analyzer_t::persistence_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::persistence);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto active = impl_->ensure_active(runtime_cancel, "persistence");
    if (!active)
        return active;
    const auto database = impl_->workspace->database();
    if (!database || !impl_->final_snapshot || !impl_->search) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::persistence_failure,
            "baseline persistence prerequisites are unavailable", "persistence"));
    }
    persisted_search_products_t products;
    products.generation = impl_->final_snapshot->generation;
    products.analysis_revision = impl_->final_snapshot->analysis_revision;
    products.overlay_revision = impl_->final_snapshot->overlay_revision;
    products.data_candidates = impl_->search->data_candidates();
    products.switches = impl_->search->switches();
    products.types = impl_->search->types();
    impl_->persistence_ticket = database->persist_snapshot(impl_->final_snapshot, std::move(products),
        impl_->settings.canonical_json(), impl_->metrics->snapshot().to_json(), impl_->cancellation.token());
    if (!impl_->persistence_ticket.accepted || !impl_->persistence_ticket.completion.valid() ||
        !impl_->persistence_ticket.snapshot_candidate) {
        impl_->discard_persistence_candidate();
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::persistence_failure,
            "workspace persistence queue rejected the baseline snapshot", "persistence"));
    }
    for (;;) {
        if (impl_->persistence_ticket.completion.wait_for(std::chrono::milliseconds(2)) ==
            std::future_status::ready)
            break;
        active = impl_->ensure_active(runtime_cancel, "persistence");
        if (!active) {
            impl_->discard_persistence_candidate();
            return active;
        }
    }
    const auto& completed = impl_->persistence_ticket.completion.get();
    if (!completed) {
        impl_->discard_persistence_candidate();
        return workspace_result_t<void>::failure(completed.error());
    }
    const auto metrics = impl_->persistence_ticket.commit_metrics;
    if (!metrics) {
        impl_->discard_persistence_candidate();
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "snapshot persistence omitted commit-local metrics", "persistence"));
    }
    const auto database_state = database->snapshot();
    std::uint64_t footprint = 0;
    std::uint64_t elapsed = 0;
    if (!checked_add_u64(database_state.database_bytes, database_state.wal_bytes, footprint) ||
        !checked_mul_u64(metrics->elapsed_us, 1000ULL, elapsed)) {
        impl_->discard_persistence_candidate();
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "persistence metric accounting overflows", "persistence"));
    }
    impl_->metrics->set(analysis_metric_t::database_bytes, footprint);
    impl_->metrics->add(analysis_metric_t::database_bytes_written, metrics->page_write_bytes);
    impl_->metrics->add(analysis_metric_t::database_logical_bytes, metrics->logical_bytes);
    impl_->metrics->add(analysis_metric_t::database_rows, metrics->rows);
    impl_->metrics->add(analysis_metric_t::database_commit_elapsed_ns, elapsed);
    impl_->metrics->add(analysis_metric_t::persistence_batches);
    impl_->metrics->end_phase(measurement, metrics->logical_bytes, metrics->page_write_bytes,
        metrics->rows, 1, false);
    return impl_->update_progress("persistence", 1, 1, footprint, footprint);
}

workspace_result_t<void> pe_baseline_analyzer_t::publish_ready_phase(
    const std::atomic<bool>& runtime_cancel) {
    auto measurement = impl_->metrics->begin_phase(baseline_phase_t::publish_ready);
    phase_completion_guard_t guard(*impl_->metrics, measurement);
    auto active = impl_->ensure_active(runtime_cancel, "publish_ready");
    if (!active)
        return active;
    if (!impl_->final_snapshot || !impl_->search || !impl_->search->matches(
            impl_->final_snapshot->generation, impl_->final_snapshot->analysis_revision,
            impl_->final_snapshot->overlay_revision) || !impl_->persistence_ticket.snapshot_candidate) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "immutable baseline products are incomplete", "publish_ready"));
    }
    const auto candidate = impl_->persistence_ticket.snapshot_candidate;
    auto published = impl_->workspace->publish_analysis_bundle(impl_->expected_generation,
        impl_->expected_analysis_revision, impl_->final_snapshot, impl_->search, true,
        [candidate] { return candidate->finalize(); });
    if (!published) {
        impl_->discard_persistence_candidate();
        return published;
    }
    impl_->metrics->end_phase(measurement, 0, 0, 1, 1, false);
    impl_->metrics->mark_finished();
    return workspace_result_t<void>::success();
}

void pe_baseline_analyzer_t::request_cancel() noexcept {
    impl_->metrics->record_cancellation_request();
    impl_->cancellation.request_cancel();
    {
        std::lock_guard<std::mutex> lock(impl_->decode_mutex);
        impl_->decode_stop = true;
    }
    impl_->decode_cv.notify_all();
}

void pe_baseline_analyzer_t::report_failure(const workspace_error_t& error) noexcept {
    bool publish = false;
    {
        std::lock_guard<std::mutex> lock(impl_->failure_mutex);
        if (!impl_->first_failure) {
            impl_->first_failure = error;
            publish = true;
        }
    }
    if (error.cancellation)
        impl_->metrics->record_cancellation_completion();
    impl_->discard_persistence_candidate();
    impl_->metrics->mark_finished();
    if (publish) {
        (void)impl_->workspace->record_analysis_attempt_failure(
            impl_->expected_generation, impl_->expected_analysis_revision, error);
    }
}

}
