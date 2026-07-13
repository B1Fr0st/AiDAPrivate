#include "hex_document.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <utility>

namespace aida {
namespace workbench {
namespace hex_document {
namespace {

bool cancellation_requested(const hex_cancellation_t* cancellation) noexcept
{
    return cancellation != nullptr && cancellation->cancelled();
}

bool range_fits(std::uint64_t address, std::uint64_t extent) noexcept
{
    return extent != 0 && extent - 1 <= (std::numeric_limits<std::uint64_t>::max)() - address;
}

bool row_pair_valid(hex_row_id_t start, hex_row_id_t end) noexcept
{
    if (!start.valid() && !end.valid())
        return true;
    return start.valid() && end.valid() && !(end < start);
}

document_kind_t target_kind(hex_cross_document_target_t target) noexcept
{
    switch (target) {
    case hex_cross_document_target_t::disassembly:
        return document_kind_t::disassembly;
    case hex_cross_document_target_t::pseudocode:
        return document_kind_t::pseudocode;
    case hex_cross_document_target_t::graph:
        return document_kind_t::graph;
    }
    return document_kind_t::unknown;
}

int hex_nibble(char value) noexcept
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -1;
}

bool separator(char value) noexcept
{
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

bool decode_hex_text(const std::string& text,
                     std::uint32_t expected_count,
                     std::vector<std::uint8_t>* output)
{
    if (output) {
        output->clear();
        output->reserve(expected_count);
    }
    std::uint32_t count = 0;
    std::size_t offset = 0;
    while (offset < text.size()) {
        while (offset < text.size() && separator(text[offset]))
            ++offset;
        if (offset == text.size())
            break;
        if (offset + 1 >= text.size())
            return false;
        const auto high = hex_nibble(text[offset]);
        const auto low = hex_nibble(text[offset + 1]);
        if (high < 0 || low < 0)
            return false;
        if (output)
            output->push_back(static_cast<std::uint8_t>((high << 4) | low));
        ++count;
        offset += 2;
        if (offset < text.size() && !separator(text[offset]))
            return false;
    }
    return count == expected_count;
}

std::string render_hex(const std::vector<std::uint8_t>& bytes)
{
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string output;
    if (bytes.empty())
        return output;
    output.reserve(bytes.size() * 3 - 1);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0)
            output.push_back(' ');
        output.push_back(digits[bytes[index] >> 4]);
        output.push_back(digits[bytes[index] & 0x0F]);
    }
    return output;
}

std::string render_ascii(const std::vector<std::uint8_t>& bytes)
{
    std::string output;
    output.reserve(bytes.size());
    for (const auto byte : bytes)
        output.push_back(byte >= 0x20 && byte <= 0x7E ? static_cast<char>(byte) : '.');
    return output;
}

}

bool hex_overlay_kind_valid(hex_overlay_kind_t kind) noexcept
{
    return kind <= hex_overlay_kind_t::highlight;
}

bool hex_page_request_valid(const hex_page_request_t& request) noexcept
{
    return request.limit != 0 && request.limit <= k_hex_document_max_page_size;
}

bool hex_selection_valid(const hex_selection_t& selection) noexcept
{
    switch (selection.kind) {
    case selection_kind_t::none:
        return !selection.has_address && selection.address == 0 && selection.extent == 0 &&
               !selection.start_row.valid() && !selection.end_row.valid();
    case selection_kind_t::address:
        return selection.has_address && selection.extent == 0 &&
               row_pair_valid(selection.start_row, selection.end_row) &&
               (!selection.start_row.valid() || selection.start_row == selection.end_row);
    case selection_kind_t::range:
        return selection.has_address && range_fits(selection.address, selection.extent) &&
               row_pair_valid(selection.start_row, selection.end_row);
    case selection_kind_t::entity:
    case selection_kind_t::source:
        return false;
    }
    return false;
}

bool hex_overlay_entry_valid(const hex_overlay_entry_t& entry) noexcept
{
    if (!hex_overlay_kind_valid(entry.kind) || !range_fits(entry.address, entry.extent) ||
        entry.extent > k_hex_document_max_patch_bytes ||
        entry.text.size() > k_hex_document_max_patch_bytes)
        return false;
    if (entry.kind == hex_overlay_kind_t::patch)
        return entry.patch_bytes.size() == entry.extent;
    return entry.patch_bytes.empty();
}

hex_error_t hex_document_model_t::fail(hex_error_code_t code,
                                        std::uint64_t subject) const noexcept
{
    return {code, subject};
}

hex_error_t hex_document_model_t::stale() const noexcept
{
    return {hex_error_code_t::stale_generation, bound_generation_};
}

hex_document_model_t::hex_document_model_t(
    const hex_source_adapter_t& source,
    const hex_overlay_adapter_t* overlays,
    const hex_navigation_adapter_t* navigation) noexcept
    : source_(&source)
    , overlays_(overlays)
    , navigation_(navigation)
    , bound_generation_(source.current_generation())
{
}

bool hex_document_model_t::lease_current(
    std::uint64_t expected_generation) const noexcept
{
    return expected_generation == bound_generation_ &&
           source_->generation_current(bound_generation_);
}

hex_error_t hex_document_model_t::bounded_total_rows(
    std::uint64_t& output) const noexcept
{
    output = 0;
    if (!source_->generation_current(bound_generation_))
        return stale();
    const auto total = source_->total_rows(bound_generation_);
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (total > k_hex_document_max_total_rows)
        return fail(hex_error_code_t::resource_exhausted, total);
    output = total;
    return {};
}

hex_error_t hex_document_model_t::validate_row(
    const hex_row_view_t& row,
    std::uint64_t ordinal,
    std::uint64_t total_rows) const noexcept
{
    const auto max_hex_length = static_cast<std::size_t>(
        k_hex_document_bytes_per_row * 3 - 1);
    if (ordinal >= total_rows || row.byte_count == 0 ||
        row.byte_count > k_hex_document_bytes_per_row ||
        row.byte_count - 1 > (std::numeric_limits<std::uint64_t>::max)() - row.address ||
        row.hex_text.size() > max_hex_length ||
        (!row.ascii_text.empty() && row.ascii_text.size() != row.byte_count) ||
        (!row.bytes.empty() && row.bytes.size() != row.byte_count) ||
        (!row.bytes.empty() && !row.hex_text.empty() &&
         !decode_hex_text(row.hex_text, row.byte_count, nullptr)) ||
        (row.bytes.empty() && !decode_hex_text(row.hex_text, row.byte_count, nullptr))) {
        return fail(hex_error_code_t::adapter_rejected, ordinal);
    }
    return {};
}

hex_error_t hex_document_model_t::load_overlays(
    std::uint64_t generation,
    const hex_cancellation_t* cancellation,
    std::vector<hex_overlay_entry_t>& output) const
{
    output.clear();
    if (!overlays_)
        return {};
    const auto count = overlays_->overlay_count(generation);
    if (!source_->generation_current(generation))
        return stale();
    if (count > k_hex_document_max_overlays)
        return fail(hex_error_code_t::overlay_capacity, count);
    output.reserve(count);
    for (std::uint32_t ordinal = 0; ordinal < count; ++ordinal) {
        if (cancellation_requested(cancellation)) {
            output.clear();
            return fail(hex_error_code_t::cancelled, ordinal);
        }
        hex_overlay_entry_t entry;
        if (!overlays_->overlay_at(generation, ordinal, entry)) {
            output.clear();
            return source_->generation_current(generation)
                ? fail(hex_error_code_t::adapter_rejected, ordinal) : stale();
        }
        if (!source_->generation_current(generation)) {
            output.clear();
            return stale();
        }
        if (!hex_overlay_entry_valid(entry)) {
            output.clear();
            return fail(hex_error_code_t::adapter_rejected, entry.address);
        }
        if (entry.active)
            output.push_back(std::move(entry));
    }
    std::stable_sort(output.begin(), output.end(),
        [](const hex_overlay_entry_t& lhs, const hex_overlay_entry_t& rhs) {
            if (lhs.revision != rhs.revision)
                return lhs.revision < rhs.revision;
            return lhs.address < rhs.address;
        });
    if (!source_->generation_current(generation)) {
        output.clear();
        return stale();
    }
    return {};
}

hex_error_t hex_document_model_t::merge_overlays(
    hex_row_view_t& row,
    const std::vector<hex_overlay_entry_t>& overlays) const
{
    row.overlays.clear();
    if (!row.hex_text.empty()) {
        std::vector<std::uint8_t> decoded;
        if (!decode_hex_text(row.hex_text, row.byte_count, &decoded) ||
            (!row.bytes.empty() && row.bytes != decoded)) {
            return fail(hex_error_code_t::adapter_rejected, row.address);
        }
        if (row.bytes.empty())
            row.bytes = std::move(decoded);
    }

    const auto row_last = row.address + row.byte_count - 1;
    for (const auto& entry : overlays) {
        const auto overlay_last = entry.address + entry.extent - 1;
        if (overlay_last < row.address || entry.address > row_last)
            continue;
        const auto projection_begin = (std::max)(row.address, entry.address);
        const auto projection_last = (std::min)(row_last, overlay_last);
        const auto source_offset = projection_begin - entry.address;
        const auto row_offset = projection_begin - row.address;
        const auto projection_extent = projection_last - projection_begin + 1;

        hex_overlay_entry_t projection = entry;
        projection.address = projection_begin;
        projection.extent = projection_extent;
        if (entry.kind == hex_overlay_kind_t::patch) {
            const auto begin = entry.patch_bytes.begin() + static_cast<std::ptrdiff_t>(source_offset);
            const auto end = begin + static_cast<std::ptrdiff_t>(projection_extent);
            projection.patch_bytes.assign(begin, end);
            std::copy(projection.patch_bytes.begin(), projection.patch_bytes.end(),
                      row.bytes.begin() + static_cast<std::ptrdiff_t>(row_offset));
        }
        row.overlays.push_back(std::move(projection));
    }

    row.hex_text = render_hex(row.bytes);
    row.ascii_text = render_ascii(row.bytes);
    return {};
}

hex_error_t hex_document_model_t::page(
    const hex_page_request_t& request,
    const hex_cancellation_t* cancellation,
    hex_page_t& output) const
{
    output = {};
    if (!hex_page_request_valid(request))
        return fail(hex_error_code_t::invalid_page, request.limit);

    std::uint64_t total = 0;
    auto error = bounded_total_rows(total);
    if (!error)
        return error;

    output.snapshot_generation = bound_generation_;
    output.total_rows = total;
    output.offset = request.offset;
    if (total == 0 || request.offset >= total) {
        if (!source_->generation_current(bound_generation_)) {
            output = {};
            return stale();
        }
        return {};
    }

    const auto overlay_revision = overlays_
        ? source_->overlay_revision(bound_generation_) : 0;
    std::vector<hex_overlay_entry_t> overlays;
    error = load_overlays(bound_generation_, cancellation, overlays);
    if (!error) {
        output = {};
        return error;
    }

    const auto remaining = total - request.offset;
    const auto to_read = (std::min)(static_cast<std::uint64_t>(request.limit), remaining);
    output.rows.reserve(static_cast<std::size_t>(to_read));
    for (std::uint64_t index = 0; index < to_read; ++index) {
        if (cancellation_requested(cancellation)) {
            output = {};
            return fail(hex_error_code_t::cancelled, index);
        }
        const auto ordinal = request.offset + index;
        hex_row_view_t row;
        if (!source_->row_at(bound_generation_, ordinal, row)) {
            output = {};
            return source_->generation_current(bound_generation_)
                ? fail(hex_error_code_t::adapter_rejected, ordinal) : stale();
        }
        if (!source_->generation_current(bound_generation_)) {
            output = {};
            return stale();
        }
        error = validate_row(row, ordinal, total);
        if (!error) {
            output = {};
            return error;
        }
        row.id = hex_row_id_t{ordinal + 1};
        error = merge_overlays(row, overlays);
        if (!error) {
            output = {};
            return error;
        }
        output.rows.push_back(std::move(row));
    }

    if (!source_->generation_current(bound_generation_)) {
        output = {};
        return stale();
    }
    if (overlays_ && source_->overlay_revision(bound_generation_) != overlay_revision) {
        output = {};
        return fail(hex_error_code_t::adapter_rejected, overlay_revision);
    }
    output.next_offset = request.offset + output.rows.size();
    if (output.next_offset >= total)
        output.next_offset = 0;
    return {};
}

hex_error_t hex_document_model_t::navigate(
    const hex_navigation_request_t& request,
    std::uint64_t expected_generation,
    hex_navigation_result_t& output) const
{
    output = {};
    if (!lease_current(expected_generation))
        return stale();

    std::uint64_t total = 0;
    auto error = bounded_total_rows(total);
    if (!error)
        return error;
    hex_row_view_t row;
    std::uint64_t ordinal = 0;
    if (!source_->row_by_address(bound_generation_, request.address, row, ordinal))
        return source_->generation_current(bound_generation_)
            ? fail(hex_error_code_t::navigation_rejected, request.address) : stale();
    if (!source_->generation_current(bound_generation_))
        return stale();
    error = validate_row(row, ordinal, total);
    if (!error)
        return error;
    if (request.address < row.address || request.address - row.address >= row.byte_count)
        return fail(hex_error_code_t::navigation_rejected, request.address);
    if (!source_->generation_current(bound_generation_))
        return stale();

    output.found = true;
    output.row = hex_row_id_t{ordinal + 1};
    output.page_offset = (ordinal / k_hex_document_max_page_size) *
                         k_hex_document_max_page_size;
    return {};
}

hex_error_t hex_document_model_t::canonicalize_selection(
    const hex_selection_t& selection,
    hex_selection_t& output) const
{
    output = {};
    if (!hex_selection_valid(selection))
        return fail(hex_error_code_t::selection_rejected,
                    static_cast<std::uint64_t>(selection.kind));
    if (selection.kind == selection_kind_t::none)
        return {};

    std::uint64_t total = 0;
    auto error = bounded_total_rows(total);
    if (!error)
        return error;
    hex_row_view_t start;
    std::uint64_t start_ordinal = 0;
    if (!source_->row_by_address(bound_generation_, selection.address, start, start_ordinal))
        return source_->generation_current(bound_generation_)
            ? fail(hex_error_code_t::selection_rejected, selection.address) : stale();
    if (!source_->generation_current(bound_generation_))
        return stale();
    error = validate_row(start, start_ordinal, total);
    if (!error)
        return error;
    if (selection.address < start.address || selection.address - start.address >= start.byte_count)
        return fail(hex_error_code_t::selection_rejected, selection.address);

    const hex_row_id_t start_id{start_ordinal + 1};
    hex_row_id_t end_id = start_id;
    if (selection.kind == selection_kind_t::range) {
        const auto last_address = selection.address + selection.extent - 1;
        hex_row_view_t end;
        std::uint64_t end_ordinal = 0;
        if (!source_->row_by_address(bound_generation_, last_address, end, end_ordinal))
            return source_->generation_current(bound_generation_)
                ? fail(hex_error_code_t::selection_rejected, last_address) : stale();
        if (!source_->generation_current(bound_generation_))
            return stale();
        error = validate_row(end, end_ordinal, total);
        if (!error)
            return error;
        if (last_address < end.address || last_address - end.address >= end.byte_count)
            return fail(hex_error_code_t::selection_rejected, last_address);
        end_id = hex_row_id_t{end_ordinal + 1};
        if (end_id < start_id)
            return fail(hex_error_code_t::selection_rejected, last_address);
    }

    if ((selection.start_row.valid() && selection.start_row != start_id) ||
        (selection.end_row.valid() && selection.end_row != end_id)) {
        return fail(hex_error_code_t::selection_rejected, selection.address);
    }
    if (!source_->generation_current(bound_generation_))
        return stale();
    output = selection;
    output.start_row = start_id;
    output.end_row = end_id;
    return {};
}

hex_error_t hex_document_model_t::select(
    const hex_selection_t& selection,
    std::uint64_t expected_generation)
{
    if (!lease_current(expected_generation))
        return stale();
    hex_selection_t canonical;
    auto error = canonicalize_selection(selection, canonical);
    if (!error)
        return error;
    selection_ = canonical;
    return {};
}

void hex_document_model_t::clear_selection() noexcept
{
    selection_ = {};
}

hex_error_t hex_document_model_t::apply_overlay(
    std::uint64_t expected_generation,
    const hex_overlay_entry_t& entry)
{
    if (!lease_current(expected_generation))
        return stale();
    if (!hex_overlay_entry_valid(entry))
        return fail(hex_error_code_t::invalid_argument,
                    static_cast<std::uint64_t>(entry.kind));
    if (!overlays_)
        return fail(hex_error_code_t::adapter_rejected);

    hex_overlay_entry_t existing;
    const auto replacing = overlays_->overlay_by_address(bound_generation_, entry.address, existing);
    const auto count = overlays_->overlay_count(bound_generation_);
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (!replacing && count >= k_hex_document_max_overlays)
        return fail(hex_error_code_t::overlay_capacity, k_hex_document_max_overlays);
    const auto wb_error = overlays_->apply_overlay(bound_generation_, entry);
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (!wb_error)
        return fail(hex_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(wb_error.code));
    return {};
}

hex_error_t hex_document_model_t::remove_overlay(
    std::uint64_t expected_generation,
    std::uint64_t address)
{
    if (!lease_current(expected_generation))
        return stale();
    if (!overlays_)
        return fail(hex_error_code_t::adapter_rejected);
    hex_overlay_entry_t existing;
    const auto found = overlays_->overlay_by_address(bound_generation_, address, existing);
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (!found)
        return fail(hex_error_code_t::overlay_not_found, address);
    const auto wb_error = overlays_->remove_overlay(bound_generation_, address);
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (!wb_error)
        return fail(hex_error_code_t::adapter_rejected,
                    static_cast<std::uint64_t>(wb_error.code));
    return {};
}

hex_error_t hex_document_model_t::cross_document(
    const hex_cross_document_request_t& request,
    hex_cross_document_result_t& output) const
{
    output = {};
    if (!source_->generation_current(bound_generation_))
        return stale();
    if (!navigation_ || target_kind(request.target) == document_kind_t::unknown ||
        request.source_document.kind != document_kind_t::hex ||
        !validate_document_identity(request.source_document)) {
        return fail(hex_error_code_t::cross_document_rejected, request.address);
    }
    const auto wb_error = navigation_->resolve_cross_document(request, output);
    if (!source_->generation_current(bound_generation_)) {
        output = {};
        return stale();
    }
    if (!wb_error)
        return fail(hex_error_code_t::cross_document_rejected,
                    static_cast<std::uint64_t>(wb_error.code));
    if (!output.resolved || output.target_document.kind != target_kind(request.target) ||
        output.target_document.workspace != request.source_document.workspace ||
        !validate_document_identity(output.target_document) ||
        !validate_selection_context(output.target_selection) ||
        !validate_document_local_cursor(output.target_cursor)) {
        output = {};
        return fail(hex_error_code_t::cross_document_rejected, request.address);
    }
    return {};
}

hex_error_t hex_document_model_t::emit_navigation_event(
    const hex_navigation_event_bridge_request_t& request,
    navigation_event_t& output) const
{
    output = {};
    if (!validate_view_context(request.source) ||
        request.source.workspace != request.navigation.source_document.workspace)
        return fail(hex_error_code_t::navigation_rejected, request.id.value);

    hex_cross_document_result_t resolved;
    auto error = cross_document(request.navigation, resolved);
    if (!error)
        return error;

    output.id = request.id;
    output.workspace = request.source.workspace;
    output.has_source = true;
    output.source = request.source;
    output.target.document = std::move(resolved.target_document);
    output.target.selection = std::move(resolved.target_selection);
    output.target.cursor = resolved.target_cursor;
    output.origin = request.origin;
    output.sequence = request.sequence;
    output.request_focus = request.request_focus;
    const auto wb_error = validate_navigation_event(output);
    if (!wb_error) {
        output = {};
        return fail(hex_error_code_t::navigation_rejected,
                    static_cast<std::uint64_t>(wb_error.code));
    }
    return {};
}

hex_error_t hex_document_model_t::apply_navigation_event(
    const navigation_event_t& event,
    std::uint64_t expected_generation,
    hex_navigation_result_t& output)
{
    output = {};
    const auto wb_error = validate_navigation_event(event);
    if (!wb_error || event.target.document.kind != document_kind_t::hex)
        return fail(hex_error_code_t::navigation_rejected, event.id.value);
    if (!lease_current(expected_generation))
        return stale();

    bool has_address = event.target.selection.has_address;
    auto address = event.target.selection.address;
    if (!has_address && event.target.document.has_address) {
        has_address = true;
        address = event.target.document.address;
    }
    if (!has_address)
        return fail(hex_error_code_t::navigation_rejected, event.id.value);

    hex_navigation_request_t navigation;
    navigation.address = address;
    navigation.select_row = event.target.selection.kind != selection_kind_t::none;
    navigation.request_focus = event.request_focus;
    auto error = navigate(navigation, expected_generation, output);
    if (!error)
        return error;
    if (event.target.selection.kind == selection_kind_t::none) {
        clear_selection();
        return {};
    }
    if (event.target.selection.kind != selection_kind_t::address &&
        event.target.selection.kind != selection_kind_t::range)
        return fail(hex_error_code_t::selection_rejected, event.id.value);

    hex_selection_t selection;
    selection.kind = event.target.selection.kind;
    selection.has_address = true;
    selection.address = event.target.selection.address;
    selection.extent = event.target.selection.extent;
    return select(selection, expected_generation);
}

hex_command_result_t hex_document_model_t::execute(
    const hex_command_t& command,
    const hex_cancellation_t* cancellation)
{
    hex_command_result_t result;
    const auto require_lease = [&]() {
        if (lease_current(command.expected_generation))
            return true;
        result.error = stale();
        return false;
    };

    switch (command.kind) {
    case hex_command_kind_t::page:
        if (require_lease()) {
            result.error = page(command.page_request, cancellation, result.page);
            result.changed = result.error.ok() && !result.page.rows.empty();
        }
        break;
    case hex_command_kind_t::navigate:
        result.error = navigate(command.navigation, command.expected_generation, result.navigation);
        result.changed = result.error.ok() && result.navigation.found;
        if (result.changed && command.navigation.select_row) {
            hex_selection_t selection;
            selection.kind = selection_kind_t::address;
            selection.has_address = true;
            selection.address = command.navigation.address;
            result.error = select(selection, command.expected_generation);
            result.changed = result.error.ok();
            if (result.changed)
                result.selection = selection_;
        }
        break;
    case hex_command_kind_t::select:
        result.error = select(command.selection, command.expected_generation);
        result.selection = selection_;
        result.changed = result.error.ok();
        break;
    case hex_command_kind_t::apply_overlay:
        result.error = apply_overlay(command.expected_generation, command.overlay);
        result.changed = result.error.ok();
        break;
    case hex_command_kind_t::remove_overlay:
        result.error = remove_overlay(command.expected_generation, command.overlay_address);
        result.changed = result.error.ok();
        break;
    case hex_command_kind_t::clear_selection:
        if (require_lease()) {
            result.changed = selection_.kind != selection_kind_t::none;
            clear_selection();
        }
        break;
    case hex_command_kind_t::refresh: {
        if (require_lease()) {
            const auto new_generation = source_->current_generation();
            if (new_generation != bound_generation_) {
                bound_generation_ = new_generation;
                selection_ = {};
                result.changed = true;
            }
        }
        break;
    }
    case hex_command_kind_t::cross_document:
        if (require_lease()) {
            result.error = cross_document(command.cross_document, result.cross_document);
            result.changed = result.error.ok() && result.cross_document.resolved;
        }
        break;
    case hex_command_kind_t::emit_navigation_event:
        if (require_lease()) {
            result.error = emit_navigation_event(command.navigation_event_bridge,
                                                 result.navigation_event);
            result.has_navigation_event = result.error.ok();
            result.changed = result.has_navigation_event;
        }
        break;
    case hex_command_kind_t::apply_navigation_event:
        result.error = apply_navigation_event(command.navigation_event,
                                              command.expected_generation,
                                              result.navigation);
        result.selection = selection_;
        result.changed = result.error.ok() && result.navigation.found;
        break;
    default:
        result.error = fail(hex_error_code_t::invalid_argument,
                            static_cast<std::uint64_t>(command.kind));
        break;
    }
    return result;
}

std::uint64_t hex_document_model_t::current_generation() const noexcept
{
    return source_->current_generation();
}

bool hex_document_model_t::generation_current(
    std::uint64_t generation) const noexcept
{
    return lease_current(generation);
}

std::uint64_t hex_document_model_t::total_rows() const noexcept
{
    if (!source_->generation_current(bound_generation_))
        return 0;
    const auto total = source_->total_rows(bound_generation_);
    if (!source_->generation_current(bound_generation_))
        return 0;
    return (std::min)(total, k_hex_document_max_total_rows);
}

const hex_selection_t& hex_document_model_t::selection() const noexcept
{
    return selection_;
}

std::uint32_t hex_document_model_t::overlay_count() const noexcept
{
    if (!overlays_ || !source_->generation_current(bound_generation_))
        return 0;
    const auto count = overlays_->overlay_count(bound_generation_);
    if (!source_->generation_current(bound_generation_))
        return 0;
    return (std::min)(count, k_hex_document_max_overlays);
}

bool hex_document_model_t::is_stale() const noexcept
{
    return !source_->generation_current(bound_generation_);
}

std::uint64_t hex_document_model_t::bound_generation() const noexcept
{
    return bound_generation_;
}

}
}
}
