#include "pseudocode_document.hpp"

#include <algorithm>
#include <chrono>

namespace aida {
namespace workbench {
namespace pseudocode_document {
namespace {

std::uint64_t now_ms() noexcept
{
    const auto tp = std::chrono::steady_clock::now();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            tp.time_since_epoch()).count());
}

}

bool pseudocode_page_request_valid(const pseudocode_page_request_t& request) noexcept
{
    return request.line_count != 0 && request.line_count <= k_pseudocode_document_max_line_length;
}

bool pseudocode_selection_valid(const pseudocode_selection_t& selection) noexcept
{
    if (selection.kind == selection_kind_t::none)
        return true;
    if (selection.kind > selection_kind_t::source)
        return false;
    return true;
}

bool pseudocode_request_valid(const pseudocode_request_t& request) noexcept
{
    if (request.timeout_ms == 0)
        return false;
    if (request.workspace_generation == 0)
        return false;
    return true;
}

std::uint32_t count_lines(const std::string& text) noexcept
{
    if (text.empty())
        return 0;
    std::uint32_t count = 1;
    for (char c : text) {
        if (c == '\n')
            ++count;
    }
    return count;
}

pseudocode_error_t pseudocode_document_model_t::fail(
    pseudocode_error_code_t code, std::uint64_t subject) noexcept
{
    return {code, subject};
}

pseudocode_error_t pseudocode_document_model_t::stale() noexcept
{
    return {pseudocode_error_code_t::stale_generation, bound_generation_};
}

pseudocode_document_model_t::pseudocode_document_model_t(
    const pseudocode_source_adapter_t& source,
    const pseudocode_navigation_adapter_t* navigation) noexcept
    : source_(&source)
    , navigation_(navigation)
    , bound_generation_(source.current_generation())
    , next_job_id_(1)
    , active_(nullptr)
{
}

pseudocode_cached_document_t* pseudocode_document_model_t::find_cached(
    const aida::analysis::decompiler_entity_key_t& entity)
{
    for (auto& entry : cache_) {
        if (entry.entity == entity)
            return &entry;
    }
    return nullptr;
}

const pseudocode_cached_document_t* pseudocode_document_model_t::find_cached(
    const aida::analysis::decompiler_entity_key_t& entity) const
{
    for (const auto& entry : cache_) {
        if (entry.entity == entity)
            return &entry;
    }
    return nullptr;
}

void pseudocode_document_model_t::evict_oldest()
{
    if (cache_.size() < k_pseudocode_document_max_cached_documents)
        return;
    auto oldest = cache_.begin();
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        if (it->cached_at_ms < oldest->cached_at_ms)
            oldest = it;
    }
    if (active_ == &(*oldest))
        active_ = nullptr;
    cache_.erase(oldest);
}

void pseudocode_document_model_t::rebuild_address_map()
{
    if (!active_ || !active_->document)
        return;
    active_->address_map.clear();
    const auto& doc = *active_->document;
    for (const auto& sm : doc.source_maps) {
        for (const auto& coord : sm.coordinates) {
            if (coord.address_range.has_value()) {
                pseudocode_address_map_entry_t entry;
                entry.address = coord.address_range->begin.value;
                entry.token_begin = sm.document_range.begin;
                entry.token_end = sm.document_range.end;
                if (coord.source_origin.has_value) {
                    entry.line_number = coord.source_origin->first_line;
                }
                active_->address_map.push_back(entry);
            }
        }
    }
    std::sort(active_->address_map.begin(), active_->address_map.end(),
              [](const auto& a, const auto& b) { return a.address < b.address; });
}

void pseudocode_document_model_t::split_lines()
{
    line_storage_.clear();
    line_views_.clear();
    if (!active_ || !active_->document)
        return;
    const auto& text = active_->document->rendered_text;
    if (text.empty())
        return;

    std::vector<std::uint32_t> line_start_offsets;
    line_start_offsets.push_back(0);
    std::uint32_t line_number = 1;
    std::size_t pos = 0;
    while (pos < text.size()) {
        auto end = text.find('\n', pos);
        if (end == std::string::npos)
            end = text.size();
        line_storage_.push_back(text.substr(pos, end - pos));
        pseudocode_line_view_t view;
        view.line_number = line_number;
        view.text = line_storage_.back();
        view.first_token = 0;
        view.token_count = 0;
        line_views_.push_back(view);
        pos = end + 1;
        ++line_number;
        if (pos < text.size())
            line_start_offsets.push_back(static_cast<std::uint32_t>(pos));
    }

    for (const auto& tok : active_->document->tokens) {
        const auto char_begin = tok.range.begin;
        auto line_idx = static_cast<std::size_t>(
            std::upper_bound(line_start_offsets.begin(), line_start_offsets.end(),
                             char_begin) - line_start_offsets.begin());
        if (line_idx > 0)
            --line_idx;
        if (line_idx < line_views_.size()) {
            if (line_views_[line_idx].first_token == 0 && line_views_[line_idx].token_count == 0)
                line_views_[line_idx].first_token = char_begin;
            ++line_views_[line_idx].token_count;
        }
    }
}

pseudocode_error_t pseudocode_document_model_t::request(
    const pseudocode_request_t& request)
{
    if (!pseudocode_request_valid(request))
        return fail(pseudocode_error_code_t::invalid_argument, 0);
    if (!source_->generation_current(request.workspace_generation))
        return stale();

    auto* existing = find_cached(request.entity);
    if (existing && existing->state == pseudocode_cache_state_t::requesting)
        return fail(pseudocode_error_code_t::request_in_progress, existing->job_id);

    if (existing) {
        if (existing->workspace_generation != request.workspace_generation) {
            existing->state = pseudocode_cache_state_t::stale;
        }
        if (existing->state == pseudocode_cache_state_t::cached &&
            existing->workspace_generation == request.workspace_generation) {
            active_ = existing;
            return {};
        }
    }

    evict_oldest();

    const auto job_id = next_job_id_++;
    pseudocode_cached_document_t entry;
    entry.entity = request.entity;
    entry.workspace_generation = request.workspace_generation;
    entry.state = pseudocode_cache_state_t::requesting;
    entry.job_id = job_id;
    entry.cached_at_ms = now_ms();
    entry.profile_info.profile = request.profile;
    const auto budget = source_->profile_budget(request.profile);
    entry.profile_info.max_wall_clock_ms = budget.max_wall_clock_ms;
    entry.profile_info.max_cpu_ms = budget.max_cpu_ms;
    entry.profile_info.max_memory_bytes = budget.max_memory_bytes;

    auto wb_err = source_->request_decompilation(request, job_id);
    if (!wb_err)
        return fail(pseudocode_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(wb_err.code));

    if (existing) {
        *existing = std::move(entry);
        active_ = existing;
    } else {
        cache_.push_back(std::move(entry));
        active_ = &cache_.back();
    }

    return {};
}

pseudocode_error_t pseudocode_document_model_t::cancel(std::uint64_t job_id)
{
    for (auto& entry : cache_) {
        if (entry.job_id == job_id) {
            if (entry.state != pseudocode_cache_state_t::requesting)
                return fail(pseudocode_error_code_t::no_active_request, job_id);
            auto wb_err = source_->cancel_decompilation(job_id);
            if (!wb_err)
                return fail(pseudocode_error_code_t::adapter_rejected,
                            static_cast<std::uint64_t>(wb_err.code));
            entry.state = pseudocode_cache_state_t::cancelled;
            return {};
        }
    }
    return fail(pseudocode_error_code_t::no_active_request, job_id);
}

pseudocode_error_t pseudocode_document_model_t::poll(std::uint64_t job_id)
{
    for (auto& entry : cache_) {
        if (entry.job_id != job_id)
            continue;
        if (entry.state != pseudocode_cache_state_t::requesting)
            return fail(pseudocode_error_code_t::no_active_request, job_id);
        if (!source_->job_active(job_id)) {
            aida::analysis::decompiler_document_t doc;
            if (source_->poll_result(job_id, doc)) {
                entry.document = std::make_shared<aida::analysis::decompiler_document_t>(std::move(doc));
                entry.state = pseudocode_cache_state_t::cached;
                entry.profile_info.elapsed_ms = now_ms() - entry.cached_at_ms;
                active_ = &entry;
                split_lines();
                rebuild_address_map();
                return {};
            }
            std::vector<aida::analysis::decompiler_diagnostic_t> diags;
            if (source_->poll_failure(job_id, diags)) {
                entry.failure_diagnostics = std::move(diags);
                entry.state = pseudocode_cache_state_t::failed;
                return fail(pseudocode_error_code_t::worker_failure, job_id);
            }
            entry.state = pseudocode_cache_state_t::failed;
            return fail(pseudocode_error_code_t::worker_failure, job_id);
        }
        return {};
    }
    return fail(pseudocode_error_code_t::no_active_request, job_id);
}

pseudocode_error_t pseudocode_document_model_t::page(
    const pseudocode_page_request_t& request,
    pseudocode_page_t& output) const
{
    if (!pseudocode_page_request_valid(request))
        return fail(pseudocode_error_code_t::invalid_argument, request.line_count);
    if (!active_)
        return fail(pseudocode_error_code_t::cache_miss, 0);

    output.workspace_generation = active_->workspace_generation;
    output.cache_state = active_->state;
    output.total_lines = static_cast<std::uint32_t>(line_views_.size());
    output.first_line = request.first_line;

    if (active_->state != pseudocode_cache_state_t::cached) {
        output.total_lines = 0;
        return {};
    }

    if (request.first_line >= line_views_.size()) {
        return {};
    }

    const auto remaining = static_cast<std::uint32_t>(line_views_.size()) - request.first_line;
    const auto to_read = (std::min)(request.line_count, remaining);

    output.lines.clear();
    output.lines.reserve(to_read);
    for (std::uint32_t i = 0; i < to_read; ++i) {
        output.lines.push_back(line_views_[request.first_line + i]);
    }

    return {};
}

pseudocode_error_t pseudocode_document_model_t::select(
    const pseudocode_selection_t& selection)
{
    if (!pseudocode_selection_valid(selection))
        return fail(pseudocode_error_code_t::invalid_argument,
                    static_cast<std::uint64_t>(selection.kind));
    selection_ = selection;
    return {};
}

void pseudocode_document_model_t::clear_selection() noexcept
{
    selection_ = {};
}

pseudocode_error_t pseudocode_document_model_t::resolve_address(
    std::uint64_t address,
    pseudocode_address_map_entry_t& output) const
{
    if (!active_ || active_->state != pseudocode_cache_state_t::cached)
        return fail(pseudocode_error_code_t::cache_miss, 0);
    if (navigation_) {
        auto wb_err = navigation_->resolve_address_to_token(
            address, *active_->document, output);
        if (!wb_err)
            return fail(pseudocode_error_code_t::address_not_mapped, address);
        return {};
    }
    auto it = std::lower_bound(active_->address_map.begin(),
                               active_->address_map.end(), address,
                               [](const auto& e, std::uint64_t a) { return e.address < a; });
    if (it == active_->address_map.end() || it->address != address)
        return fail(pseudocode_error_code_t::address_not_mapped, address);
    output = *it;
    return {};
}

pseudocode_error_t pseudocode_document_model_t::resolve_token(
    std::uint32_t token_begin,
    pseudocode_address_map_entry_t& output) const
{
    if (!active_ || active_->state != pseudocode_cache_state_t::cached)
        return fail(pseudocode_error_code_t::cache_miss, 0);
    if (navigation_) {
        auto wb_err = navigation_->resolve_token_to_address(
            token_begin, *active_->document, output);
        if (!wb_err)
            return fail(pseudocode_error_code_t::token_not_mapped, token_begin);
        return {};
    }
    for (const auto& entry : active_->address_map) {
        if (token_begin >= entry.token_begin && token_begin < entry.token_end) {
            output = entry;
            return {};
        }
    }
    return fail(pseudocode_error_code_t::token_not_mapped, token_begin);
}

void pseudocode_document_model_t::refresh() noexcept
{
    const auto new_gen = source_->current_generation();
    if (new_gen != bound_generation_) {
        bound_generation_ = new_gen;
        for (auto& entry : cache_) {
            if (entry.state == pseudocode_cache_state_t::cached)
                entry.state = pseudocode_cache_state_t::stale;
        }
    }
}

pseudocode_command_result_t pseudocode_document_model_t::execute(
    const pseudocode_command_t& command)
{
    pseudocode_command_result_t result;

    switch (command.kind) {
    case pseudocode_command_kind_t::request: {
        result.error = request(command.request);
        if (active_)
            result.job_id = active_->job_id;
        result.cache_state = active_ ? active_->state : pseudocode_cache_state_t::empty;
        result.changed = result.error.ok();
        break;
    }
    case pseudocode_command_kind_t::cancel: {
        result.error = cancel(command.job_id);
        result.changed = result.error.ok();
        break;
    }
    case pseudocode_command_kind_t::poll: {
        result.error = poll(command.job_id);
        result.cache_state = active_ ? active_->state : pseudocode_cache_state_t::empty;
        result.changed = result.error.ok() &&
                         result.cache_state == pseudocode_cache_state_t::cached;
        break;
    }
    case pseudocode_command_kind_t::page: {
        result.error = page(command.page_request, result.page);
        result.cache_state = active_ ? active_->state : pseudocode_cache_state_t::empty;
        result.changed = result.error.ok() && !result.page.lines.empty();
        break;
    }
    case pseudocode_command_kind_t::select: {
        result.error = select(command.selection);
        result.selection = selection_;
        result.changed = result.error.ok();
        break;
    }
    case pseudocode_command_kind_t::clear_selection: {
        clear_selection();
        result.changed = true;
        break;
    }
    case pseudocode_command_kind_t::refresh: {
        refresh();
        result.cache_state = active_ ? active_->state : pseudocode_cache_state_t::empty;
        result.changed = true;
        break;
    }
    case pseudocode_command_kind_t::resolve_address: {
        result.error = resolve_address(command.resolve_address, result.address_map_entry);
        result.changed = result.error.ok();
        break;
    }
    case pseudocode_command_kind_t::resolve_token: {
        result.error = resolve_token(command.resolve_token, result.address_map_entry);
        result.changed = result.error.ok();
        break;
    }
    default:
        result.error = fail(pseudocode_error_code_t::invalid_argument,
                            static_cast<std::uint64_t>(command.kind));
        break;
    }

    return result;
}

pseudocode_cache_state_t pseudocode_document_model_t::cache_state() const noexcept
{
    return active_ ? active_->state : pseudocode_cache_state_t::empty;
}

const pseudocode_cached_document_t* pseudocode_document_model_t::cached_document() const noexcept
{
    return active_;
}

std::uint64_t pseudocode_document_model_t::current_generation() const noexcept
{
    return source_->current_generation();
}

bool pseudocode_document_model_t::generation_current(
    std::uint64_t generation) const noexcept
{
    return source_->generation_current(generation);
}

bool pseudocode_document_model_t::is_stale() const noexcept
{
    if (!source_->generation_current(bound_generation_))
        return true;
    if (active_ && active_->state == pseudocode_cache_state_t::stale)
        return true;
    return false;
}

std::uint32_t pseudocode_document_model_t::cached_document_count() const noexcept
{
    return static_cast<std::uint32_t>(cache_.size());
}

const pseudocode_selection_t& pseudocode_document_model_t::selection() const noexcept
{
    return selection_;
}

const pseudocode_profile_info_t& pseudocode_document_model_t::profile_info() const noexcept
{
    if (active_)
        return active_->profile_info;
    return profile_info_;
}

std::vector<pseudocode_diagnostic_view_t>
pseudocode_document_model_t::diagnostics() const
{
    std::vector<pseudocode_diagnostic_view_t> result;
    if (!active_)
        return result;
    if (active_->state == pseudocode_cache_state_t::failed) {
        for (const auto& diag : active_->failure_diagnostics) {
            pseudocode_diagnostic_view_t view;
            view.severity = diag.severity;
            view.code = diag.code;
            view.localization_key = diag.localization_key;
            view.retryable = diag.retryable;
            if (diag.coordinate.has_value() &&
                diag.coordinate->source_origin.has_value()) {
                view.has_line = true;
                view.line = diag.coordinate->source_origin->first_line;
            }
            result.push_back(view);
        }
    } else if (active_->document) {
        for (const auto& diag : active_->document->diagnostics) {
            pseudocode_diagnostic_view_t view;
            view.severity = diag.severity;
            view.code = diag.code;
            view.localization_key = diag.localization_key;
            view.retryable = diag.retryable;
            if (diag.coordinate.has_value() &&
                diag.coordinate->source_origin.has_value()) {
                view.has_line = true;
                view.line = diag.coordinate->source_origin->first_line;
            }
            result.push_back(view);
        }
    }
    if (result.size() > k_pseudocode_document_max_diagnostics)
        result.resize(k_pseudocode_document_max_diagnostics);
    return result;
}

}
}
}
