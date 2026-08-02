#include "flirt_engine.hpp"

#include "../workspace/parallel_pass.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <new>

namespace aida::analysis::flirt {
namespace {

struct section_view_t {
    std::uint64_t virtual_address = 0;
    std::uint64_t virtual_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
};

struct scan_context_t {
    std::vector<section_view_t> sections;
    std::vector<std::uint32_t> reloc_rvas;
    const flirt_signature_db_t* db = nullptr;
    std::shared_ptr<const byte_provider_t> provider;
    std::uint64_t max_candidates = 64;
    std::uint64_t max_pattern_bytes = 32;
    bool relocation_check = true;
};

const section_view_t* find_section(const scan_context_t& ctx, std::uint64_t rva) noexcept
{
    std::size_t lo = 0;
    std::size_t hi = ctx.sections.size();
    while (lo < hi) {
        const std::size_t mid = (lo + hi) / 2;
        if (ctx.sections[mid].virtual_address <= rva)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo == 0)
        return nullptr;
    const section_view_t& section = ctx.sections[lo - 1];
    if (rva < section.virtual_address ||
        rva - section.virtual_address >= section.virtual_size)
        return nullptr;
    return &section;
}

bool reloc_in_range(const scan_context_t& ctx, std::uint64_t begin, std::uint64_t end,
                    std::uint32_t mask, std::uint64_t start) noexcept
{
    auto first = std::lower_bound(ctx.reloc_rvas.begin(), ctx.reloc_rvas.end(),
                                  static_cast<std::uint32_t>(begin));
    for (auto it = first; it != ctx.reloc_rvas.end() && *it < end; ++it) {
        const std::uint64_t delta = *it - start;
        if (delta < 32 && (mask & (1u << delta)) != 0)
            return true;
    }
    return false;
}

struct candidate_outcome_t {
    std::uint32_t db_entry = 0;
    std::uint32_t score = 0;
    std::uint8_t tier = 0;
    std::uint8_t confidence = 0;
    std::string_view name;
    bool is_noreturn = false;
};

struct shard_result_t {
    std::vector<flirt_match_t> matches;
    std::uint64_t considered = 0;
    std::uint64_t skipped_thunk = 0;
    std::uint64_t skipped_short = 0;
    std::uint64_t candidates = 0;
    std::uint64_t ambiguous = 0;
    std::uint64_t rejected_reloc = 0;
};

void match_function(const scan_context_t& ctx, std::uint64_t start, std::uint64_t end,
                    const std::uint8_t* bytes, std::size_t available,
                    shard_result_t& out)
{
    std::uint64_t prefix8 = 0;
    std::memcpy(&prefix8, bytes, sizeof(prefix8));
    const auto bucket = ctx.db->bucket(prefix8);
    if (bucket.second == 0)
        return;
    std::vector<candidate_outcome_t> survivors;
    survivors.reserve((std::min<std::uint64_t>)(bucket.second, ctx.max_candidates));
    const std::uint64_t tested_limit = (std::min<std::uint64_t>)(bucket.second, ctx.max_candidates);
    for (std::uint32_t ordinal = 0; ordinal < tested_limit; ++ordinal) {
        ++out.candidates;
        flirt_db_entry_view_t sig;
        if (!ctx.db->entry(bucket.first + ordinal, sig))
            continue;
        if (sig.pattern_len > available || sig.pattern_len > ctx.max_pattern_bytes)
            continue;
        bool pattern_ok = true;
        for (std::size_t i = 0; i < sig.pattern_len; ++i) {
            if ((sig.mask & (1u << i)) != 0 && bytes[i] != sig.bytes[i]) {
                pattern_ok = false;
                break;
            }
        }
        if (!pattern_ok)
            continue;
        if (ctx.relocation_check && !ctx.reloc_rvas.empty() &&
            reloc_in_range(ctx, start, start + sig.pattern_len, sig.mask, start)) {
            ++out.rejected_reloc;
            continue;
        }
        candidate_outcome_t outcome;
        outcome.db_entry = sig.index;
        outcome.score = 1;
        std::uint8_t tail[k_afdb_max_pattern_bytes]{};
        for (std::size_t i = k_afdb_prefix_bytes; i < sig.pattern_len; ++i)
            if ((sig.mask & (1u << i)) != 0)
                tail[i] = bytes[i];
        if (crc16_ccitt_false(tail + k_afdb_prefix_bytes,
                              sig.pattern_len - k_afdb_prefix_bytes) == sig.tail_crc16)
            outcome.score += 2;
        if (sig.func_size != 0 && end > start && end - start == sig.func_size)
            outcome.score += 1;
        outcome.name = sig.name;
        outcome.is_noreturn = (sig.sig_flags & k_afdb_sig_flag_noreturn) != 0;
        if (outcome.score >= 4) {
            outcome.tier = k_flirt_tier_exact_size;
            outcome.confidence = 230;
        } else if (outcome.score >= 3) {
            outcome.tier = k_flirt_tier_exact_crc;
            outcome.confidence = 200;
        } else {
            outcome.tier = k_flirt_tier_pattern_only;
            outcome.confidence = 170;
        }
        survivors.push_back(outcome);
    }
    if (survivors.empty())
        return;
    std::uint32_t top_score = 0;
    for (const auto& survivor : survivors)
        top_score = (std::max<std::uint32_t>)(top_score, survivor.score);
    std::size_t top_count = 0;
    std::string_view top_name;
    bool same_name = true;
    const candidate_outcome_t* top = nullptr;
    for (const auto& survivor : survivors) {
        if (survivor.score != top_score)
            continue;
        if (top_count == 0) {
            top_name = survivor.name;
            top = &survivor;
        } else if (survivor.name != top_name) {
            same_name = false;
        }
        ++top_count;
    }
    if (!top)
        return;
    if (top->tier == k_flirt_tier_pattern_only && survivors.size() != 1) {
        ++out.ambiguous;
        return;
    }
    if (!same_name) {
        ++out.ambiguous;
        return;
    }
    flirt_match_t match;
    match.rva = start;
    match.name.assign(top_name.data(), top_name.size());
    match.tier = top->tier;
    match.confidence = top->confidence;
    match.db_entry = top->db_entry;
    match.is_noreturn = top->is_noreturn;
    out.matches.push_back(std::move(match));
}

}

workspace_result_t<flirt_scan_result_t>
flirt_scan(const flirt_scan_request_t& request, const cancellation_token_t& cancel)
{
    const auto begun = std::chrono::steady_clock::now();
    flirt_scan_result_t result;
    auto finish = [&](std::uint8_t status) {
        result.status = status;
        result.elapsed_ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - begun).count();
        diag::log_tagged_fmt("flirt",
            "scan exit status=%u considered=%llu thunk=%llu short=%llu candidates=%llu matches=%zu ambiguous=%llu rejected_reloc=%llu elapsed_ms=%.1f",
            static_cast<unsigned int>(status),
            static_cast<unsigned long long>(result.functions_considered),
            static_cast<unsigned long long>(result.functions_skipped_thunk),
            static_cast<unsigned long long>(result.functions_skipped_short),
            static_cast<unsigned long long>(result.candidates_tested),
            result.matches.size(),
            static_cast<unsigned long long>(result.ambiguous),
            static_cast<unsigned long long>(result.rejected_reloc),
            result.elapsed_ms);
        return workspace_result_t<flirt_scan_result_t>::success(std::move(result));
    };
    if (!request.snapshot || !request.image || !request.provider)
        return finish(k_flirt_status_invalid);
    if (!request.db || request.db->empty()) {
        diag::log_tagged_fmt("flirt", "scan skip db_absent=1");
        return finish(k_flirt_status_db_absent);
    }
    if (cancel.stop_requested())
        return finish(k_flirt_status_cancelled);

    scan_context_t ctx;
    ctx.db = request.db;
    ctx.provider = request.provider;
    ctx.max_candidates = request.limits.max_candidates_per_function;
    ctx.max_pattern_bytes = request.limits.max_pattern_bytes;
    ctx.relocation_check = request.limits.relocation_check && request.pe != nullptr;
    ctx.sections.reserve(request.image->sections.size());
    for (const auto& section : request.image->sections) {
        if (section.file_size == 0 || section.virtual_size == 0)
            continue;
        section_view_t view;
        view.virtual_address = section.virtual_address;
        view.virtual_size = section.virtual_size;
        view.file_offset = section.file_offset;
        view.file_size = section.file_size;
        ctx.sections.push_back(view);
    }
    std::sort(ctx.sections.begin(), ctx.sections.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.virtual_address < rhs.virtual_address;
    });
    if (ctx.relocation_check) {
        ctx.reloc_rvas.reserve(request.pe->relocations().size());
        for (const auto& relocation : request.pe->relocations())
            ctx.reloc_rvas.push_back(relocation.rva);
        std::sort(ctx.reloc_rvas.begin(), ctx.reloc_rvas.end());
    }

    std::vector<std::uint64_t> starts;
    std::vector<std::uint64_t> ends;
    const auto& functions = request.snapshot->functions;
    starts.reserve((std::min<std::uint64_t>)(functions.size(), request.limits.max_functions));
    ends.reserve(starts.capacity());
    for (const auto& function : functions) {
        if (starts.size() >= request.limits.max_functions)
            break;
        if (function.thunk) {
            ++result.functions_skipped_thunk;
            continue;
        }
        starts.push_back(function.start.value);
        ends.push_back(function.end.value);
    }

    diag::log_tagged_fmt("flirt",
        "scan enter functions=%zu db_entries=%u db_buckets=%zu reloc=%u",
        starts.size(), request.db->entry_count(), request.db->bucket_count(),
        ctx.relocation_check ? 1u : 0u);

    const auto shards = parallel_shards(starts.size(), request.limits.workers);
    std::vector<shard_result_t> shard_results(shards.size());
    std::atomic<bool> aborted{false};
    const auto gate = [&] { return !cancel.stop_requested() && !aborted.load(std::memory_order_acquire); };
    try {
        parallel_executor_t::run_gated(shards.size(), request.limits.workers,
            "flirt.anchored_scan", gate, [&](std::size_t shard_index) {
                const auto& shard = shards[shard_index];
                auto& local = shard_results[shard_index];
                for (std::size_t index = shard.begin; index < shard.end; ++index) {
                    if (((index - shard.begin) & 0xFFFu) == 0 && cancel.stop_requested()) {
                        aborted.store(true, std::memory_order_release);
                        return;
                    }
                    const std::uint64_t start = starts[index];
                    const section_view_t* section = find_section(ctx, start);
                    if (!section) {
                        ++local.skipped_short;
                        continue;
                    }
                    const std::uint64_t file_offset =
                        section->file_offset + (start - section->virtual_address);
                    const std::uint64_t section_file_end = section->file_offset + section->file_size;
                    if (file_offset >= section_file_end || section_file_end - file_offset < 16) {
                        ++local.skipped_short;
                        continue;
                    }
                    const std::uint64_t wanted =
                        (std::min<std::uint64_t>)(ctx.max_pattern_bytes, section_file_end - file_offset);
                    ++local.considered;
                    auto leased = ctx.provider->lease(file_offset, wanted, cancel);
                    if (!leased || leased.value().size() < 16)
                        continue;
                    std::uint8_t buffer[k_afdb_max_pattern_bytes]{};
                    leased.value().copy_to(buffer, (std::min<std::size_t>)(
                        leased.value().size(), k_afdb_max_pattern_bytes));
                    match_function(ctx, start, ends[index], buffer,
                                   (std::min<std::size_t>)(leased.value().size(),
                                                           k_afdb_max_pattern_bytes), local);
                }
            });
    } catch (const std::bad_alloc&) {
        return workspace_result_t<flirt_scan_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "FLIRT scan exceeded available memory", "flirt.scan"));
    } catch (...) {
        return workspace_result_t<flirt_scan_result_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "FLIRT scan worker failed unexpectedly", "flirt.scan"));
    }
    for (auto& local : shard_results) {
        result.matches.reserve(result.matches.size() + local.matches.size());
        for (auto& match : local.matches)
            result.matches.push_back(std::move(match));
        result.functions_considered += local.considered;
        result.functions_skipped_short += local.skipped_short;
        result.candidates_tested += local.candidates;
        result.ambiguous += local.ambiguous;
        result.rejected_reloc += local.rejected_reloc;
    }
    if (aborted.load(std::memory_order_acquire) || cancel.stop_requested())
        return finish(k_flirt_status_cancelled);
    return finish(k_flirt_status_completed);
}

}
