#include "decode_frontier.hpp"

#include "frontier_pending_store.hpp"

#include <algorithm>
#include <deque>
#include <limits>
#include <new>
#include <string>
#include <unordered_set>
#include <utility>

namespace aida::analysis {
namespace {

constexpr const char* kPhase = "decode_frontier";

workspace_error_t frontier_error(workspace_error_code_t code, std::string message,
                                 std::optional<std::uint64_t> rva = std::nullopt)
{
    auto error = make_workspace_error(code, std::move(message), kPhase);
    if (rva) {
        address_t address;
        address.space = address_space_id_t::relative_virtual;
        address.value = *rva;
        error.address = address;
    }
    return error;
}

bool seed_kind_valid(decode_frontier_seed_kind_t kind) noexcept
{
    return kind >= decode_frontier_seed_kind_t::fallthrough &&
           kind <= decode_frontier_seed_kind_t::explicit_entry;
}

bool provenance_valid(fact_provenance_t provenance) noexcept
{
    return provenance >= fact_provenance_t::unknown &&
           provenance <= fact_provenance_t::decompiler_feedback;
}

bool stronger_seed(const decode_frontier_seed_t& left,
                   const decode_frontier_seed_t& right) noexcept
{
    const auto left_priority = decode_frontier_seed_priority(left.kind);
    const auto right_priority = decode_frontier_seed_priority(right.kind);
    if (left_priority != right_priority)
        return left_priority > right_priority;
    const auto left_provenance = provenance_rank(left.provenance);
    const auto right_provenance = provenance_rank(right.provenance);
    if (left_provenance != right_provenance)
        return left_provenance > right_provenance;
    if (left.confidence != right.confidence)
        return left.confidence > right.confidence;
    if (left.stable_source_id != right.stable_source_id)
        return left.stable_source_id < right.stable_source_id;
    return left.source_rva < right.source_rva;
}

bool stronger_claim(const decode_frontier_claim_t& left,
                    const decode_frontier_claim_t& right) noexcept
{
    const auto left_provenance = provenance_rank(left.provenance);
    const auto right_provenance = provenance_rank(right.provenance);
    if (left_provenance != right_provenance)
        return left_provenance > right_provenance;
    if (left.confidence != right.confidence)
        return left.confidence > right.confidence;
    return left.stable_source_id < right.stable_source_id;
}

struct claimed_flat_set_t final {
    static constexpr std::uint32_t npos = 0xFFFFFFFFu;

    std::vector<std::uint64_t> keys;
    std::vector<decode_frontier_claim_t> claims;
    std::uint32_t size = 0;
    std::uint32_t mask = 0;

    std::uint32_t find(std::uint64_t rva) const noexcept
    {
        if (keys.empty())
            return npos;
        const std::uint64_t key = rva + 1;
        std::uint32_t slot = static_cast<std::uint32_t>(
            (key * 0x9E3779B97F4A7C15ULL) >> 32) & mask;
        for (;;) {
            const auto current = keys[slot];
            if (current == 0)
                return npos;
            if (current == key)
                return slot;
            slot = (slot + 1) & mask;
        }
    }

    std::uint32_t insert(std::uint64_t rva)
    {
        if (keys.empty()) {
            keys.assign(64, 0);
            claims.assign(64, decode_frontier_claim_t{});
            mask = 63;
        } else if ((static_cast<std::uint64_t>(size) + 1ULL) * 10ULL >=
                   static_cast<std::uint64_t>(keys.size()) * 7ULL) {
            grow();
        }
        const std::uint64_t key = rva + 1;
        std::uint32_t slot = static_cast<std::uint32_t>(
            (key * 0x9E3779B97F4A7C15ULL) >> 32) & mask;
        while (keys[slot] != 0 && keys[slot] != key)
            slot = (slot + 1) & mask;
        if (keys[slot] == 0) {
            keys[slot] = key;
            claims[slot] = decode_frontier_claim_t{};
            ++size;
            return slot;
        }
        return slot;
    }

    void grow()
    {
        std::vector<std::uint64_t> previous_keys = std::move(keys);
        std::vector<decode_frontier_claim_t> previous_claims = std::move(claims);
        const std::size_t capacity = previous_keys.size() * 2;
        keys.assign(capacity, 0);
        claims.assign(capacity, decode_frontier_claim_t{});
        mask = static_cast<std::uint32_t>(capacity - 1);
        size = 0;
        for (std::size_t index = 0; index < previous_keys.size(); ++index) {
            const auto key = previous_keys[index];
            if (key == 0)
                continue;
            std::uint32_t slot = static_cast<std::uint32_t>(
                (key * 0x9E3779B97F4A7C15ULL) >> 32) & mask;
            while (keys[slot] != 0)
                slot = (slot + 1) & mask;
            keys[slot] = key;
            claims[slot] = previous_claims[index];
            ++size;
        }
    }
};

}

struct decode_frontier_t::impl_t final {
    using pending_store_t =
        frontier_pending_store_t<std::uint64_t, decode_frontier_seed_t>;

    struct tile_state_t final {
        decode_frontier_tile_t tile;
        pending_store_t pending;
        claimed_flat_set_t claimed;
        bool in_queue = false;
    };

    std::vector<decode_frontier_tile_t> tiles;
    std::vector<tile_state_t> states;
    std::deque<std::uint32_t> pending_queue;
    std::uint64_t maximum_unique_seeds = 0;
    decode_frontier_snapshot_t counters;
    std::atomic<std::uint64_t>* shared_unique_seed_count = nullptr;
    std::shared_ptr<frontier_pending_arena_t> pending_arena;

    void note_pending_insert(std::size_t index)
    {
        auto& state = states[index];
        if (state.in_queue)
            return;
        pending_queue.push_back(static_cast<std::uint32_t>(index));
        state.in_queue = true;
    }

    std::optional<std::size_t> locate_index(std::uint64_t rva) const noexcept
    {
        const auto found = std::upper_bound(
            tiles.begin(), tiles.end(), rva,
            [](std::uint64_t value, const decode_frontier_tile_t& tile) {
                return value < tile.start_rva;
            });
        if (found == tiles.begin())
            return std::nullopt;
        const auto candidate = static_cast<std::size_t>(std::distance(tiles.begin(), found) - 1);
        const auto& tile = tiles[candidate];
        if (rva < tile.start_rva || rva - tile.start_rva >= tile.byte_count)
            return std::nullopt;
        return candidate;
    }

    bool try_consume_seed_budget() noexcept
    {
        if (shared_unique_seed_count == nullptr)
            return counters.unique_seed_count < maximum_unique_seeds;
        auto current = shared_unique_seed_count->load(std::memory_order_relaxed);
        for (;;) {
            if (current >= maximum_unique_seeds)
                return false;
            if (shared_unique_seed_count->compare_exchange_weak(
                    current, current + 1, std::memory_order_acq_rel))
                return true;
        }
    }
};

std::uint8_t decode_frontier_seed_priority(decode_frontier_seed_kind_t kind) noexcept
{
    switch (kind) {
    case decode_frontier_seed_kind_t::fallthrough:
        return 1;
    case decode_frontier_seed_kind_t::branch_target:
        return 2;
    case decode_frontier_seed_kind_t::call_target:
        return 3;
    case decode_frontier_seed_kind_t::range_entry:
        return 4;
    case decode_frontier_seed_kind_t::explicit_entry:
        return 5;
    }
    return 0;
}

workspace_result_t<decode_frontier_t> decode_frontier_t::build(
    std::vector<decode_frontier_tile_t> tiles,
    std::uint64_t maximum_unique_seeds)
{
    return build(std::move(tiles), maximum_unique_seeds, nullptr);
}

workspace_result_t<decode_frontier_t> decode_frontier_t::build(
    std::vector<decode_frontier_tile_t> tiles,
    std::uint64_t maximum_unique_seeds,
    std::atomic<std::uint64_t>* shared_unique_seed_count)
{
    if (maximum_unique_seeds == 0) {
        return workspace_result_t<decode_frontier_t>::failure(frontier_error(
            workspace_error_code_t::invalid_argument,
            "decode frontier requires a non-zero seed budget"));
    }
    std::sort(tiles.begin(), tiles.end(), [](const auto& left, const auto& right) {
        if (left.start_rva != right.start_rva)
            return left.start_rva < right.start_rva;
        return left.id < right.id;
    });
    std::uint64_t previous_end = 0;
    bool have_previous = false;
    std::unordered_set<decode_tile_id_t> ids;
    ids.reserve(tiles.size());
    for (const auto& tile : tiles) {
        if (tile.byte_count == 0 ||
            tile.start_rva > (std::numeric_limits<std::uint64_t>::max)() - tile.byte_count) {
            return workspace_result_t<decode_frontier_t>::failure(frontier_error(
                workspace_error_code_t::range_overflow,
                "decode frontier tile range is empty or overflows", tile.start_rva));
        }
        if (!ids.insert(tile.id).second) {
            return workspace_result_t<decode_frontier_t>::failure(frontier_error(
                workspace_error_code_t::duplicate_target,
                "decode frontier tile identifier is duplicated", tile.start_rva));
        }
        if (have_previous && tile.start_rva < previous_end) {
            return workspace_result_t<decode_frontier_t>::failure(frontier_error(
                workspace_error_code_t::target_conflict,
                "decode frontier tile ranges overlap", tile.start_rva));
        }
        previous_end = tile.start_rva + tile.byte_count;
        have_previous = true;
    }
    try {
        auto impl = std::make_unique<impl_t>();
        impl->tiles = std::move(tiles);
        impl->maximum_unique_seeds = maximum_unique_seeds;
        impl->shared_unique_seed_count = shared_unique_seed_count;
        impl->pending_arena = std::make_shared<frontier_pending_arena_t>();
        impl->states.reserve(impl->tiles.size());
        for (const auto& tile : impl->tiles) {
            impl->states.push_back(impl_t::tile_state_t{
                tile, impl_t::pending_store_t(impl->pending_arena), {}});
        }
        return workspace_result_t<decode_frontier_t>::success(
            decode_frontier_t(std::move(impl)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<decode_frontier_t>::failure(frontier_error(
            workspace_error_code_t::limit_exceeded,
            "decode frontier allocation failed"));
    }
}

decode_frontier_t::decode_frontier_t(std::unique_ptr<impl_t> impl) noexcept
    : impl_(std::move(impl))
{
}

decode_frontier_t::decode_frontier_t(decode_frontier_t&&) noexcept = default;
decode_frontier_t& decode_frontier_t::operator=(decode_frontier_t&&) noexcept = default;
decode_frontier_t::~decode_frontier_t() = default;

workspace_result_t<decode_frontier_add_result_t> decode_frontier_t::add_seed(
    decode_frontier_seed_t seed,
    std::optional<decode_tile_id_t> source_tile)
{
    if (!impl_ || !seed_kind_valid(seed.kind) || !provenance_valid(seed.provenance) ||
        seed.confidence > 100) {
        return workspace_result_t<decode_frontier_add_result_t>::failure(frontier_error(
            workspace_error_code_t::invalid_argument,
            "decode frontier seed is invalid", seed.rva));
    }
    const auto index = impl_->locate_index(seed.rva);
    if (!index) {
        ++impl_->counters.outside_seed_count;
        decode_frontier_add_result_t result;
        result.disposition = decode_frontier_add_disposition_t::outside_executable;
        return workspace_result_t<decode_frontier_add_result_t>::success(result);
    }
    auto& state = impl_->states[*index];
    seed.tile_id = state.tile.id;
    decode_frontier_add_result_t result;
    result.tile_id = state.tile.id;
    result.cross_tile = source_tile.has_value() && *source_tile != state.tile.id;
    const auto claimed_slot = state.claimed.find(seed.rva);
    if (claimed_slot != claimed_flat_set_t::npos) {
        const auto requeued = state.pending.find(seed.rva);
        if (requeued != state.pending.end()) {
            if (stronger_seed(seed, requeued->second)) {
                requeued->second = seed;
                ++impl_->counters.strengthened_seed_count;
                if (result.cross_tile)
                    ++impl_->counters.cross_tile_route_count;
                result.disposition = decode_frontier_add_disposition_t::strengthened;
            } else {
                ++impl_->counters.duplicate_seed_count;
                result.disposition = decode_frontier_add_disposition_t::already_claimed;
            }
            return workspace_result_t<decode_frontier_add_result_t>::success(result);
        }
        const decode_frontier_claim_t offer{
            seed.provenance, seed.confidence, seed.stable_source_id};
        if (!stronger_claim(offer, state.claimed.claims[claimed_slot])) {
            ++impl_->counters.duplicate_seed_count;
            result.disposition = decode_frontier_add_disposition_t::already_claimed;
            return workspace_result_t<decode_frontier_add_result_t>::success(result);
        }
        if (!impl_->try_consume_seed_budget()) {
            auto error = frontier_error(workspace_error_code_t::limit_exceeded,
                                        "decode frontier seed budget is exhausted", seed.rva);
            error.details.emplace_back("resource", "frontier_seeds");
            error.details.emplace_back("limit", std::to_string(impl_->maximum_unique_seeds));
            return workspace_result_t<decode_frontier_add_result_t>::failure(std::move(error));
        }
        try {
            state.pending.emplace(seed.rva, seed);
            impl_->note_pending_insert(*index);
        } catch (const std::bad_alloc&) {
            return workspace_result_t<decode_frontier_add_result_t>::failure(frontier_error(
                workspace_error_code_t::limit_exceeded,
                "decode frontier seed allocation failed", seed.rva));
        }
        ++impl_->counters.unique_seed_count;
        ++impl_->counters.pending_seed_count;
        if (result.cross_tile)
            ++impl_->counters.cross_tile_route_count;
        result.disposition = decode_frontier_add_disposition_t::queued;
        return workspace_result_t<decode_frontier_add_result_t>::success(result);
    }
    const auto existing = state.pending.find(seed.rva);
    if (existing != state.pending.end()) {
        if (stronger_seed(seed, existing->second)) {
            existing->second = seed;
            ++impl_->counters.strengthened_seed_count;
            if (result.cross_tile)
                ++impl_->counters.cross_tile_route_count;
            result.disposition = decode_frontier_add_disposition_t::strengthened;
        } else {
            ++impl_->counters.duplicate_seed_count;
            result.disposition = decode_frontier_add_disposition_t::duplicate;
        }
        return workspace_result_t<decode_frontier_add_result_t>::success(result);
    }
    if (!impl_->try_consume_seed_budget()) {
        auto error = frontier_error(workspace_error_code_t::limit_exceeded,
                                    "decode frontier seed budget is exhausted", seed.rva);
        error.details.emplace_back("resource", "frontier_seeds");
        error.details.emplace_back("limit", std::to_string(impl_->maximum_unique_seeds));
        return workspace_result_t<decode_frontier_add_result_t>::failure(std::move(error));
    }
    try {
        state.pending.emplace(seed.rva, seed);
        impl_->note_pending_insert(*index);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<decode_frontier_add_result_t>::failure(frontier_error(
            workspace_error_code_t::limit_exceeded,
            "decode frontier seed allocation failed", seed.rva));
    }
    ++impl_->counters.unique_seed_count;
    ++impl_->counters.pending_seed_count;
    if (result.cross_tile)
        ++impl_->counters.cross_tile_route_count;
    result.disposition = decode_frontier_add_disposition_t::queued;
    return workspace_result_t<decode_frontier_add_result_t>::success(result);
}

workspace_result_t<std::vector<decode_frontier_seed_t>> decode_frontier_t::take_wave(
    std::uint64_t maximum_items)
{
    if (!impl_ || maximum_items == 0 ||
        maximum_items > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        return workspace_result_t<std::vector<decode_frontier_seed_t>>::failure(frontier_error(
            workspace_error_code_t::invalid_argument,
            "decode frontier wave limit is invalid"));
    }
    try {
        std::vector<decode_frontier_seed_t> wave;
        wave.reserve(static_cast<std::size_t>(
            (std::min)(maximum_items, impl_->counters.pending_seed_count)));
        while (wave.size() < maximum_items && !impl_->pending_queue.empty()) {
            const auto index = impl_->pending_queue.front();
            impl_->pending_queue.pop_front();
            auto& state = impl_->states[static_cast<std::size_t>(index)];
            state.in_queue = false;
            if (state.pending.empty())
                continue;
            auto found = state.pending.begin();
            auto seed = found->second;
            state.pending.erase(found);
            const auto claim_slot = state.claimed.insert(seed.rva);
            const decode_frontier_claim_t claim{
                seed.provenance, seed.confidence, seed.stable_source_id};
            if (!stronger_claim(state.claimed.claims[claim_slot], claim))
                state.claimed.claims[claim_slot] = claim;
            wave.push_back(std::move(seed));
            --impl_->counters.pending_seed_count;
            ++impl_->counters.claimed_seed_count;
            if (!state.pending.empty()) {
                impl_->pending_queue.push_back(index);
                state.in_queue = true;
            }
        }
        return workspace_result_t<std::vector<decode_frontier_seed_t>>::success(
            std::move(wave));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::vector<decode_frontier_seed_t>>::failure(frontier_error(
            workspace_error_code_t::limit_exceeded,
            "decode frontier wave allocation failed"));
    }
}

workspace_result_t<void> decode_frontier_t::mark_claimed(decode_tile_id_t tile_id,
                                                         std::uint64_t rva)
{
    if (!impl_)
        return workspace_result_t<void>::failure(frontier_error(
            workspace_error_code_t::integrity_failure,
            "decode frontier state is unavailable", rva));
    const auto index = impl_->locate_index(rva);
    if (!index || impl_->states[*index].tile.id != tile_id) {
        return workspace_result_t<void>::failure(frontier_error(
            workspace_error_code_t::out_of_range,
            "decode frontier claim is outside its tile", rva));
    }
    decode_frontier_claim_t claim;
    const auto pending = impl_->states[*index].pending.find(rva);
    if (pending != impl_->states[*index].pending.end()) {
        claim.provenance = pending->second.provenance;
        claim.confidence = pending->second.confidence;
        claim.stable_source_id = pending->second.stable_source_id;
    } else {
        claim.provenance = fact_provenance_t::unknown;
        claim.confidence = 0;
        claim.stable_source_id = (std::numeric_limits<std::uint64_t>::max)();
    }
    return mark_claimed(tile_id, rva, claim);
}

workspace_result_t<void> decode_frontier_t::mark_claimed(decode_tile_id_t tile_id,
                                                         std::uint64_t rva,
                                                         const decode_frontier_claim_t& claim)
{
    if (!impl_)
        return workspace_result_t<void>::failure(frontier_error(
            workspace_error_code_t::integrity_failure,
            "decode frontier state is unavailable", rva));
    const auto index = impl_->locate_index(rva);
    if (!index || impl_->states[*index].tile.id != tile_id) {
        return workspace_result_t<void>::failure(frontier_error(
            workspace_error_code_t::out_of_range,
            "decode frontier claim is outside its tile", rva));
    }
    auto& state = impl_->states[*index];
    const auto existing_slot = state.claimed.find(rva);
    if (existing_slot != claimed_flat_set_t::npos) {
        if (stronger_claim(claim, state.claimed.claims[existing_slot]))
            state.claimed.claims[existing_slot] = claim;
        return workspace_result_t<void>::success();
    }
    const auto pending = state.pending.find(rva);
    if (pending == state.pending.end() && !impl_->try_consume_seed_budget()) {
        auto error = frontier_error(workspace_error_code_t::limit_exceeded,
                                    "decode frontier claim budget is exhausted", rva);
        error.details.emplace_back("resource", "frontier_claims");
        error.details.emplace_back("limit", std::to_string(impl_->maximum_unique_seeds));
        return workspace_result_t<void>::failure(std::move(error));
    }
    try {
        const auto slot = state.claimed.insert(rva);
        state.claimed.claims[slot] = claim;
    } catch (const std::bad_alloc&) {
        return workspace_result_t<void>::failure(frontier_error(
            workspace_error_code_t::limit_exceeded,
            "decode frontier claim allocation failed", rva));
    }
    if (pending != state.pending.end()) {
        state.pending.erase(pending);
        --impl_->counters.pending_seed_count;
    } else {
        ++impl_->counters.unique_seed_count;
    }
    ++impl_->counters.claimed_seed_count;
    return workspace_result_t<void>::success();
}

std::optional<decode_tile_id_t> decode_frontier_t::locate_tile(std::uint64_t rva) const noexcept
{
    if (!impl_)
        return std::nullopt;
    const auto index = impl_->locate_index(rva);
    if (!index)
        return std::nullopt;
    return impl_->states[*index].tile.id;
}

bool decode_frontier_t::empty() const noexcept
{
    return !impl_ || impl_->counters.pending_seed_count == 0;
}

decode_frontier_snapshot_t decode_frontier_t::snapshot() const noexcept
{
    return impl_ ? impl_->counters : decode_frontier_snapshot_t{};
}

const std::vector<decode_frontier_tile_t>& decode_frontier_t::tiles() const noexcept
{
    static const std::vector<decode_frontier_tile_t> empty;
    return impl_ ? impl_->tiles : empty;
}

}
