#include "workbench_documents_harness.hpp"

#include "../../src/core/workbench/adapters/disasm_document.hpp"
#include "../../src/core/workbench/adapters/hex_document.hpp"
#include "../../src/core/workbench/adapters/pseudocode_document.hpp"
#include "../../src/core/workbench/adapters/graph_document.hpp"
#include "../../src/core/workbench/adapters/diff_document.hpp"
#include "../../src/core/workbench/workbench_contracts.h"
#include "../../src/core/analysis/decompiler/decompiler_contracts.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace workbench {
namespace {

void require(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}

void require(bool condition, const std::string& message)
{
    if (!condition)
        throw std::runtime_error(message);
}

class cancellation_flag_t : public disasm_document::disasm_cancellation_t,
                            public hex_document::hex_cancellation_t,
                            public graph_document::graph_layout_cancellation_t,
                            public diff_document::diff_cancellation_t {
public:
    void cancel() noexcept { cancelled_ = true; }
    bool cancelled() const noexcept override { return cancelled_; }
private:
    bool cancelled_ = false;
};

class disasm_source_t final : public disasm_document::disasm_source_adapter_t {
public:
    explicit disasm_source_t(std::uint64_t row_count)
        : row_count_(row_count)
    {
    }

    void advance_generation() { ++generation_; }

    std::uint64_t current_generation() const noexcept override { return generation_; }
    bool generation_current(std::uint64_t gen) const noexcept override
    {
        return gen == generation_;
    }
    std::uint64_t total_rows(std::uint64_t gen) const noexcept override
    {
        return gen == generation_ ? row_count_ : 0;
    }

    bool row_at(std::uint64_t gen, std::uint64_t ordinal,
                disasm_document::disasm_instruction_view_t& output) const override
    {
        if (gen != generation_ || ordinal >= row_count_)
            return false;
        output.id = disasm_document::disasm_row_id_t{ordinal + 1};
        output.address = 0x401000U + ordinal * 4;
        output.byte_size = 4;
        output.mnemonic = "nop";
        output.operands = "";
        output.raw_hex = "90 90 90 90";
        if (ordinal % 10 == 0 && ordinal > 0) {
            output.has_branch_target = true;
            output.branch_target = 0x401000U + (ordinal / 10) * 100 * 4;
        }
        return true;
    }

    bool row_by_address(std::uint64_t gen, std::uint64_t address,
                        disasm_document::disasm_instruction_view_t& output,
                        std::uint64_t& ordinal) const override
    {
        if (gen != generation_)
            return false;
        if (address < 0x401000U)
            return false;
        const auto offset = address - 0x401000U;
        ordinal = offset / 4;
        if (ordinal >= row_count_)
            return false;
        return row_at(gen, ordinal, output);
    }

    std::uint64_t overlay_revision(std::uint64_t) const noexcept override
    {
        return generation_;
    }

private:
    std::uint64_t generation_ = 1;
    std::uint64_t row_count_;
};

class disasm_overlay_t final : public disasm_document::disasm_overlay_adapter_t {
public:
    std::uint32_t overlay_count(std::uint64_t) const noexcept override
    {
        return static_cast<std::uint32_t>(entries_.size());
    }

    bool overlay_at(std::uint64_t, std::uint32_t ordinal,
                    disasm_document::disasm_overlay_entry_t& output) const override
    {
        if (ordinal >= entries_.size())
            return false;
        output = entries_[ordinal];
        return true;
    }

    bool overlay_by_address(std::uint64_t, std::uint64_t address,
                            disasm_document::disasm_overlay_entry_t& output) const override
    {
        for (const auto& e : entries_) {
            if (e.address == address && e.active) {
                output = e;
                return true;
            }
        }
        return false;
    }

    workbench_error_t apply_overlay(std::uint64_t,
                                    const disasm_document::disasm_overlay_entry_t& entry) override
    {
        for (auto& e : entries_) {
            if (e.address == entry.address) {
                e = entry;
                return {};
            }
        }
        entries_.push_back(entry);
        return {};
    }

    workbench_error_t remove_overlay(std::uint64_t,
                                     std::uint64_t address) override
    {
        auto it = std::remove_if(entries_.begin(), entries_.end(),
            [address](const auto& e) { return e.address == address; });
        if (it == entries_.end())
            return {workbench_error_code_t::invalid_document, address};
        entries_.erase(it, entries_.end());
        return {};
    }

private:
    std::vector<disasm_document::disasm_overlay_entry_t> entries_;
};

class disasm_nav_t final : public disasm_document::disasm_navigation_adapter_t {
public:
    workbench_error_t resolve_cross_document(
        const disasm_document::disasm_cross_document_request_t& request,
        disasm_document::disasm_cross_document_result_t& output) const override
    {
        output.resolved = true;
        output.target_document = request.source_document;
        output.target_document.kind = document_kind_t::hex;
        output.target_selection.kind = selection_kind_t::address;
        output.target_selection.has_address = true;
        output.target_selection.address = request.address;
        output.target_cursor.has_position = true;
        output.target_cursor.position = request.address;
        return {};
    }
};

class hex_source_t final : public hex_document::hex_source_adapter_t {
public:
    explicit hex_source_t(std::uint64_t row_count, std::uint64_t base_address = 0)
        : row_count_(row_count)
        , base_address_(base_address)
    {
    }

    void advance_generation() { ++generation_; }

    std::uint64_t current_generation() const noexcept override { return generation_; }
    bool generation_current(std::uint64_t gen) const noexcept override
    {
        return gen == generation_;
    }
    std::uint64_t total_rows(std::uint64_t gen) const noexcept override
    {
        return gen == generation_ ? row_count_ : 0;
    }

    bool row_at(std::uint64_t gen, std::uint64_t ordinal,
                hex_document::hex_row_view_t& output) const override
    {
        if (gen != generation_ || ordinal >= row_count_)
            return false;
        output.id = hex_document::hex_row_id_t{ordinal + 1};
        output.address = base_address_ + ordinal * hex_document::k_hex_document_bytes_per_row;
        output.hex_text = "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90";
        output.ascii_text = "................";
        output.bytes.assign(hex_document::k_hex_document_bytes_per_row, 0x90);
        output.byte_count = hex_document::k_hex_document_bytes_per_row;
        return true;
    }

    bool row_by_address(std::uint64_t gen, std::uint64_t address,
                        hex_document::hex_row_view_t& output,
                        std::uint64_t& ordinal) const override
    {
        if (gen != generation_)
            return false;
        if (address < base_address_)
            return false;
        ordinal = (address - base_address_) / hex_document::k_hex_document_bytes_per_row;
        if (ordinal >= row_count_)
            return false;
        return row_at(gen, ordinal, output);
    }

    std::uint64_t overlay_revision(std::uint64_t) const noexcept override
    {
        return generation_;
    }

private:
    std::uint64_t generation_ = 1;
    std::uint64_t row_count_;
    std::uint64_t base_address_ = 0;
};

class hex_overlay_t final : public hex_document::hex_overlay_adapter_t {
public:
    std::uint32_t overlay_count(std::uint64_t) const noexcept override
    {
        return static_cast<std::uint32_t>(entries_.size());
    }

    bool overlay_at(std::uint64_t, std::uint32_t ordinal,
                    hex_document::hex_overlay_entry_t& output) const override
    {
        if (ordinal >= entries_.size())
            return false;
        output = entries_[ordinal];
        return true;
    }

    bool overlay_by_address(std::uint64_t, std::uint64_t address,
                            hex_document::hex_overlay_entry_t& output) const override
    {
        for (const auto& e : entries_) {
            if (e.address == address && e.active) {
                output = e;
                return true;
            }
        }
        return false;
    }

    workbench_error_t apply_overlay(std::uint64_t,
                                    const hex_document::hex_overlay_entry_t& entry) override
    {
        for (auto& e : entries_) {
            if (e.address == entry.address) {
                e = entry;
                return {};
            }
        }
        entries_.push_back(entry);
        return {};
    }

    workbench_error_t remove_overlay(std::uint64_t,
                                     std::uint64_t address) override
    {
        auto it = std::remove_if(entries_.begin(), entries_.end(),
            [address](const auto& e) { return e.address == address; });
        if (it == entries_.end())
            return {workbench_error_code_t::invalid_document, address};
        entries_.erase(it, entries_.end());
        return {};
    }

private:
    std::vector<hex_document::hex_overlay_entry_t> entries_;
};

class hex_nav_t final : public hex_document::hex_navigation_adapter_t {
public:
    workbench_error_t resolve_cross_document(
        const hex_document::hex_cross_document_request_t& request,
        hex_document::hex_cross_document_result_t& output) const override
    {
        output.resolved = true;
        output.target_document = request.source_document;
        output.target_document.kind = document_kind_t::disassembly;
        output.target_selection.kind = selection_kind_t::address;
        output.target_selection.has_address = true;
        output.target_selection.address = request.address;
        output.target_cursor.has_position = true;
        output.target_cursor.position = request.address;
        return {};
    }
};

void verify_disasm_large_virtual_model()
{
    constexpr std::uint64_t row_count = 100'000;
    disasm_source_t source(row_count);
    disasm_document::disasm_document_model_t model(source);

    require(model.total_rows() == row_count, "disasm model total rows must match source");

    disasm_document::disasm_page_request_t req;
    req.offset = 0;
    req.limit = 100;
    disasm_document::disasm_page_t page;
    auto err = model.page(req, nullptr, page);
    require(err.ok(), "disasm page must succeed for first page");
    require(page.rows.size() == 100, "disasm first page must return exactly 100 rows");
    require(page.total_rows == row_count, "disasm page total_rows must match source");
    require(page.next_offset == 100, "disasm page next_offset must advance");

    req.offset = row_count - 50;
    req.limit = 100;
    err = model.page(req, nullptr, page);
    require(err.ok(), "disasm page must succeed for last page");
    require(page.rows.size() == 50, "disasm last page must return only remaining rows");
    require(page.next_offset == 0, "disasm last page next_offset must be zero");

    req.offset = row_count;
    req.limit = 10;
    err = model.page(req, nullptr, page);
    require(err.ok(), "disasm page past end must succeed with empty result");
    require(page.rows.empty(), "disasm page past end must return no rows");

    disasm_document::disasm_navigation_request_t nav;
    nav.address = 0x401000U + 5000 * 4;
    disasm_document::disasm_navigation_result_t nav_result;
    err = model.navigate(nav, model.current_generation(), nav_result);
    require(err.ok() && nav_result.found, "disasm navigate to existing address must succeed");
    require(nav_result.row.value == 5001, "disasm navigate row id must be ordinal+1");
}

void verify_disasm_stale_generation()
{
    disasm_source_t source(1000);
    disasm_overlay_t overlays;
    disasm_document::disasm_document_model_t model(source, &overlays);
    const auto original_gen = model.bound_generation();

    source.advance_generation();

    require(model.is_stale(), "disasm model must detect stale generation");
    require(!model.generation_current(original_gen), "disasm model must report old generation as not current");
    require(!model.generation_current(source.current_generation()),
            "disasm stale model must not accept the source's newer generation");

    disasm_document::disasm_navigation_request_t navigation;
    navigation.address = 0x401000U;
    disasm_document::disasm_navigation_result_t navigation_result;
    auto err = model.navigate(navigation, source.current_generation(), navigation_result);
    require(err.code == disasm_document::disasm_error_code_t::stale_generation,
            "disasm navigate must enforce the bound generation lease");

    disasm_document::disasm_selection_t stale_selection;
    stale_selection.kind = selection_kind_t::address;
    stale_selection.has_address = true;
    stale_selection.address = 0x401000U;
    err = model.select(stale_selection, source.current_generation());
    require(err.code == disasm_document::disasm_error_code_t::stale_generation,
            "disasm select must enforce the bound generation lease");

    disasm_document::disasm_overlay_entry_t stale_overlay;
    stale_overlay.kind = disasm_document::disasm_overlay_kind_t::comment;
    stale_overlay.address = 0x401000U;
    stale_overlay.text = "stale";
    err = model.apply_overlay(source.current_generation(), stale_overlay);
    require(err.code == disasm_document::disasm_error_code_t::stale_generation,
            "disasm overlay mutation must enforce the bound generation lease");

    disasm_document::disasm_command_t cmd;
    cmd.kind = disasm_document::disasm_command_kind_t::refresh;
    cmd.expected_generation = original_gen;
    auto result = model.execute(cmd);
    require(result.error.code ==
                disasm_document::disasm_error_code_t::stale_generation &&
                !result.changed,
            "disasm refresh must reject an expired generation lease");
    require(model.is_stale(),
            "disasm refresh must not rebind an expired generation lease");

    disasm_document::disasm_document_model_t rebound_model(source, &overlays);
    require(!rebound_model.is_stale() &&
                rebound_model.bound_generation() == source.current_generation(),
            "a new disasm model must bind the current immutable generation");

    disasm_document::disasm_page_request_t req;
    req.offset = 0;
    req.limit = 10;
    disasm_document::disasm_page_t page;
    err = rebound_model.page(req, nullptr, page);
    require(err.ok() && page.rows.size() == 10,
            "disasm page must work after shell-style model replacement");
}

void verify_disasm_overlay_visualization()
{
    disasm_source_t source(1000);
    disasm_overlay_t overlays;
    disasm_document::disasm_document_model_t model(source, &overlays);

    disasm_document::disasm_overlay_entry_t entry;
    entry.kind = disasm_document::disasm_overlay_kind_t::comment;
    entry.address = 0x401000U + 100 * 4;
    entry.text = "loop_start";
    entry.active = true;

    auto err = model.apply_overlay(model.bound_generation(), entry);
    require(err.ok(), "disasm apply overlay must succeed");
    require(model.overlay_count() == 1, "disasm overlay count must be 1 after apply");

    disasm_document::disasm_page_request_t req;
    req.offset = 98;
    req.limit = 5;
    disasm_document::disasm_page_t page;
    err = model.page(req, nullptr, page);
    require(err.ok(), "disasm page with overlay must succeed");
    require(page.rows.size() == 5, "disasm page with overlay must return rows");

    bool found_overlay = false;
    for (const auto& row : page.rows) {
        if (row.overlay) {
            found_overlay = true;
            require(row.overlay->text == "loop_start", "disasm overlay text must match");
        }
    }
    require(found_overlay, "disasm overlay must be visible on matching row");

    auto copied_page = page;
    page = {};
    require(copied_page.rows[2].overlay.has_value(),
            "disasm copied page must retain owned overlay storage");
    require(copied_page.rows[2].overlay->text == "loop_start",
            "disasm copied page overlay must remain valid after source page reset");

    err = model.remove_overlay(model.bound_generation(), entry.address);
    require(err.ok(), "disasm remove overlay must succeed");
    require(model.overlay_count() == 0, "disasm overlay count must be 0 after remove");

    err = model.remove_overlay(model.bound_generation(), 0xDEAD);
    require(!err.ok(), "disasm remove non-existent overlay must fail");
}

void verify_disasm_cross_document_navigation()
{
    disasm_source_t source(1000);
    disasm_nav_t nav;
    disasm_document::disasm_document_model_t model(source, nullptr, &nav);

    disasm_document::disasm_cross_document_request_t req;
    req.target = disasm_document::disasm_cross_document_target_t::hex;
    req.address = 0x401200U;
    req.source_document.kind = document_kind_t::disassembly;
    req.source_document.workspace = {1};
    req.source_document.object_id = 1;

    disasm_document::disasm_cross_document_result_t result;
    auto err = model.cross_document(req, result);
    require(err.ok() && result.resolved, "disasm cross-document navigation must succeed");
    require(result.target_document.kind == document_kind_t::hex,
            "disasm cross-document target must be hex document");
    require(result.target_selection.address == 0x401200U,
            "disasm cross-document selection must preserve address");
}

void verify_disasm_command_routing()
{
    disasm_source_t source(500);
    disasm_overlay_t overlays;
    disasm_document::disasm_document_model_t model(source, &overlays);

    disasm_document::disasm_command_t nav_cmd;
    nav_cmd.kind = disasm_document::disasm_command_kind_t::navigate;
    nav_cmd.expected_generation = model.bound_generation();
    nav_cmd.navigation.address = 0x401000U + 200 * 4;
    nav_cmd.navigation.select_row = true;
    auto result = model.execute(nav_cmd);
    require(result.error.ok() && result.changed, "disasm navigate command must succeed");
    require(model.selection().has_address, "disasm navigate must set selection");
    require(model.selection().address == nav_cmd.navigation.address,
            "disasm navigate selection address must match");

    disasm_document::disasm_command_t clear_cmd;
    clear_cmd.kind = disasm_document::disasm_command_kind_t::clear_selection;
    clear_cmd.expected_generation = model.bound_generation();
    result = model.execute(clear_cmd);
    require(result.changed, "disasm clear selection must report changed");
    require(model.selection().kind == selection_kind_t::none,
            "disasm selection must be none after clear");

    disasm_document::disasm_command_t page_cmd;
    page_cmd.kind = disasm_document::disasm_command_kind_t::page;
    page_cmd.expected_generation = model.bound_generation();
    page_cmd.page_request.offset = 0;
    page_cmd.page_request.limit = 50;
    result = model.execute(page_cmd);
    require(result.error.ok() && result.page.rows.size() == 50,
            "disasm page command must return rows");
}

void verify_disasm_limits_and_selection()
{
    disasm_source_t oversized(disasm_document::k_disasm_document_max_total_rows + 1);
    disasm_document::disasm_document_model_t oversized_model(oversized);
    require(oversized_model.total_rows() == disasm_document::k_disasm_document_max_total_rows,
            "disasm total_rows must remain capped at the document ceiling");

    disasm_document::disasm_page_request_t request;
    disasm_document::disasm_page_t page;
    request.limit = disasm_document::k_disasm_document_max_page_size + 1;
    auto err = oversized_model.page(request, nullptr, page);
    require(err.code == disasm_document::disasm_error_code_t::invalid_page,
            "disasm page must reject a request above the packed-page ceiling");
    request.limit = 1;
    err = oversized_model.page(request, nullptr, page);
    require(err.code == disasm_document::disasm_error_code_t::resource_exhausted,
            "disasm page must reject a source above the row ceiling");

    disasm_source_t exact(disasm_document::k_disasm_document_max_total_rows);
    disasm_document::disasm_document_model_t model(exact);
    request.offset = disasm_document::k_disasm_document_max_total_rows - 1;
    err = model.page(request, nullptr, page);
    require(err.ok() && page.rows.size() == 1,
            "disasm row ceiling must remain addressable without overflow");
    require(page.rows.front().id.value == disasm_document::k_disasm_document_max_total_rows,
            "disasm ceiling row must retain a valid one-based row id");

    disasm_document::disasm_selection_t invalid_address;
    invalid_address.kind = selection_kind_t::address;
    invalid_address.address = 0x401000U;
    err = model.select(invalid_address, model.bound_generation());
    require(err.code == disasm_document::disasm_error_code_t::selection_rejected,
            "disasm address selection must require has_address");

    disasm_document::disasm_selection_t mismatched_row;
    mismatched_row.kind = selection_kind_t::address;
    mismatched_row.has_address = true;
    mismatched_row.address = 0x401001U;
    mismatched_row.start_row = {2};
    mismatched_row.end_row = {2};
    err = model.select(mismatched_row, model.bound_generation());
    require(err.code == disasm_document::disasm_error_code_t::selection_rejected,
            "disasm selection must reject a row id that does not contain the address");

    disasm_document::disasm_selection_t range;
    range.kind = selection_kind_t::range;
    range.has_address = true;
    range.address = 0x401002U;
    range.extent = 6;
    err = model.select(range, model.bound_generation());
    require(err.ok(), "disasm range selection across instruction interiors must succeed");
    require(model.selection().start_row.value == 1 && model.selection().end_row.value == 2,
            "disasm range selection must canonicalize both boundary rows");

    range.address = (std::numeric_limits<std::uint64_t>::max)();
    range.extent = 2;
    err = model.select(range, model.bound_generation());
    require(err.code == disasm_document::disasm_error_code_t::selection_rejected,
            "disasm range selection must reject address overflow");
}

void verify_navigation_event_bridge()
{
    disasm_source_t disasm_source(1000);
    hex_source_t hex_source(1000, 0x400000U);
    disasm_nav_t disasm_navigation;
    hex_nav_t hex_navigation;
    disasm_document::disasm_document_model_t disasm_model(
        disasm_source, nullptr, &disasm_navigation);
    hex_document::hex_document_model_t hex_model(
        hex_source, nullptr, &hex_navigation);

    disasm_document::disasm_navigation_event_bridge_request_t outbound;
    outbound.id = {1};
    outbound.sequence = 1;
    outbound.source.workspace = {1};
    outbound.source.document = {10};
    outbound.source.view = {20};
    outbound.navigation.target = disasm_document::disasm_cross_document_target_t::hex;
    outbound.navigation.address = 0x401200U;
    outbound.navigation.source_document.workspace = {1};
    outbound.navigation.source_document.kind = document_kind_t::disassembly;
    outbound.navigation.source_document.object_id = 1;

    disasm_document::disasm_command_t emit_command;
    emit_command.kind = disasm_document::disasm_command_kind_t::emit_navigation_event;
    emit_command.expected_generation = disasm_model.bound_generation();
    emit_command.navigation_event_bridge = outbound;
    auto emitted = disasm_model.execute(emit_command);
    require(emitted.error.ok() && emitted.has_navigation_event,
            "disasm command bridge must emit a workbench navigation event");
    require(validate_navigation_event(emitted.navigation_event).ok(),
            "disasm emitted navigation event must satisfy the workbench contract");

    hex_document::hex_command_t apply_command;
    apply_command.kind = hex_document::hex_command_kind_t::apply_navigation_event;
    apply_command.expected_generation = hex_model.bound_generation();
    apply_command.navigation_event = emitted.navigation_event;
    auto applied = hex_model.execute(apply_command);
    require(applied.error.ok() && applied.navigation.found,
            "hex command bridge must apply a workbench navigation event");
    require(hex_model.selection().address == outbound.navigation.address,
            "hex navigation bridge must synchronize the target address");

    hex_document::hex_navigation_event_bridge_request_t reverse;
    reverse.id = {2};
    reverse.sequence = 2;
    reverse.source.workspace = {1};
    reverse.source.document = {11};
    reverse.source.view = {21};
    reverse.navigation.target = hex_document::hex_cross_document_target_t::disassembly;
    reverse.navigation.address = 0x401204U;
    reverse.navigation.source_document.workspace = {1};
    reverse.navigation.source_document.kind = document_kind_t::hex;
    reverse.navigation.source_document.object_id = 2;

    navigation_event_t reverse_event;
    const auto hex_emit_error = hex_model.emit_navigation_event(reverse, reverse_event);
    require(hex_emit_error.ok() && validate_navigation_event(reverse_event).ok(),
            "hex bridge must emit a valid reverse navigation event");
    disasm_document::disasm_navigation_result_t disasm_result;
    auto disasm_apply_error = disasm_model.apply_navigation_event(
        reverse_event, disasm_model.bound_generation(), disasm_result);
    require(disasm_apply_error.ok() && disasm_result.found,
            "disasm bridge must apply a reverse navigation event");
    require(disasm_model.selection().address == reverse.navigation.address,
            "disasm navigation bridge must synchronize the target address");

    auto clear_event = emitted.navigation_event;
    clear_event.id = {3};
    clear_event.sequence = 3;
    clear_event.target.selection = {};
    clear_event.target.document.has_address = true;
    clear_event.target.document.address = outbound.navigation.address;
    hex_document::hex_navigation_result_t clear_result;
    const auto clear_error = hex_model.apply_navigation_event(
        clear_event, hex_model.bound_generation(), clear_result);
    require(clear_error.ok() && clear_result.found &&
                hex_model.selection().kind == selection_kind_t::none,
            "hex navigation bridge must apply an explicit empty target selection");

    hex_source.advance_generation();
    hex_document::hex_navigation_result_t stale_hex_result;
    const auto stale_hex_error = hex_model.apply_navigation_event(
        emitted.navigation_event, hex_source.current_generation(), stale_hex_result);
    require(stale_hex_error.code == hex_document::hex_error_code_t::stale_generation,
            "hex navigation bridge must reject the source's newer generation before refresh");

    disasm_source.advance_generation();
    disasm_apply_error = disasm_model.apply_navigation_event(
        reverse_event, disasm_source.current_generation(), disasm_result);
    require(disasm_apply_error.code == disasm_document::disasm_error_code_t::stale_generation,
            "disasm navigation bridge must reject the source's newer generation before refresh");
}

void verify_production_document_bridge()
{
    const workspace_id_t workspace{41};
    workbench_document_bridge_t bridge(workspace);

    document_descriptor_t disassembly;
    disassembly.identity.workspace = workspace;
    disassembly.identity.kind = document_kind_t::disassembly;
    disassembly.identity.object_id = 7;
    disassembly.identity.provider_key = "analysis";
    disassembly.title = "Disassembly";
    disassembly.can_open = true;

    auto hex = disassembly;
    hex.identity.kind = document_kind_t::hex;
    hex.title = "Hex";

    auto graph = disassembly;
    graph.identity.kind = document_kind_t::graph;
    graph.title = "Graph";

    auto error = bridge.replace({disassembly, hex, graph});
    require(error.ok() && bridge.documents().size() == 3,
            "production document bridge must publish the shell document catalog");

    navigation_resolution_t target;
    error = bridge.resolve_target(disassembly.identity, document_kind_t::hex,
                                  0x401240U, target);
    require(error.ok() && target.requires_document_open &&
                target.document.kind == document_kind_t::hex &&
                target.document.has_address &&
                target.document.address == 0x401240U &&
                target.selection.kind == selection_kind_t::address &&
                target.selection.address == 0x401240U,
            "production document bridge must resolve an address-bearing center view");

    document_descriptor_t described;
    error = bridge.describe(target.document, described);
    require(error.ok() && described.identity.has_address &&
                described.identity.address == target.document.address &&
                described.title == hex.title,
            "production document bridge must describe dynamic address identities");

    document_navigation_bridge_request_t request;
    request.id = {9};
    request.sequence = 12;
    request.origin = navigation_origin_t::adapter;
    request.source.workspace = workspace;
    request.source.document = {3};
    request.source.view = {5};
    request.target.document = target.document;
    request.target.selection = target.selection;
    request.target.cursor = target.cursor;

    navigation_event_t event;
    error = bridge.emit(request, event);
    require(error.ok() && validate_navigation_event(event).ok(),
            "production document bridge must emit a valid workbench event");

    navigation_resolution_t resolved;
    error = bridge.resolve(event, resolved);
    require(error.ok() && resolved.requires_document_open &&
                document_identity_equal(resolved.document, target.document) &&
                selection_context_equal(resolved.selection, target.selection),
            "production document bridge must resolve its emitted event");
}

void verify_hex_large_virtual_model()
{
    constexpr std::uint64_t row_count = 50'000;
    hex_source_t source(row_count);
    hex_document::hex_document_model_t model(source);

    require(model.total_rows() == row_count, "hex model total rows must match source");

    hex_document::hex_page_request_t req;
    req.offset = 0;
    req.limit = 200;
    hex_document::hex_page_t page;
    auto err = model.page(req, nullptr, page);
    require(err.ok(), "hex page must succeed");
    require(page.rows.size() == 200, "hex first page must return 200 rows");

    req.offset = row_count - 10;
    req.limit = 200;
    err = model.page(req, nullptr, page);
    require(err.ok() && page.rows.size() == 10, "hex last page must return remaining rows");
}

void verify_hex_stale_and_overlay()
{
    hex_source_t source(1000);
    hex_overlay_t overlays;
    hex_document::hex_document_model_t model(source, &overlays);

    hex_document::hex_overlay_entry_t patch;
    patch.kind = hex_document::hex_overlay_kind_t::patch;
    patch.address = 0x100;
    patch.extent = 4;
    patch.patch_bytes = {0xCC, 0xCC, 0xCC, 0xCC};
    patch.text = "int3 patch";

    auto err = model.apply_overlay(model.bound_generation(), patch);
    require(err.ok(), "hex apply patch overlay must succeed");
    require(model.overlay_count() == 1, "hex overlay count must be 1");

    source.advance_generation();
    require(model.is_stale(), "hex model must detect stale generation");
    require(!model.generation_current(source.current_generation()),
            "hex stale model must not accept the source's newer generation");

    hex_document::hex_navigation_request_t navigation;
    navigation.address = 0x100;
    hex_document::hex_navigation_result_t navigation_result;
    err = model.navigate(navigation, source.current_generation(), navigation_result);
    require(err.code == hex_document::hex_error_code_t::stale_generation,
            "hex navigate must enforce the bound generation lease");
    err = model.apply_overlay(source.current_generation(), patch);
    require(err.code == hex_document::hex_error_code_t::stale_generation,
            "hex overlay mutation must enforce the bound generation lease");

    hex_document::hex_command_t cmd;
    cmd.kind = hex_document::hex_command_kind_t::refresh;
    cmd.expected_generation = model.bound_generation();
    auto result = model.execute(cmd);
    require(result.error.code == hex_document::hex_error_code_t::stale_generation &&
                !result.changed,
            "hex refresh must reject an expired generation lease");
    require(model.is_stale(),
            "hex refresh must not rebind an expired generation lease");

    hex_document::hex_document_model_t rebound_model(source, &overlays);
    require(!rebound_model.is_stale() &&
                rebound_model.bound_generation() == source.current_generation(),
            "a new hex model must bind the current immutable generation");
}

void verify_hex_patch_projection_limits_and_selection()
{
    hex_source_t source(4);
    hex_overlay_t overlays;
    hex_document::hex_document_model_t model(source, &overlays);

    hex_document::hex_overlay_entry_t patch;
    patch.kind = hex_document::hex_overlay_kind_t::patch;
    patch.revision = 7;
    patch.address = 14;
    patch.extent = 6;
    patch.patch_bytes = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x41};
    patch.text = "cross-row patch";
    auto err = model.apply_overlay(model.bound_generation(), patch);
    require(err.ok(), "hex cross-row patch must be accepted");

    hex_document::hex_page_request_t request;
    request.limit = 2;
    hex_document::hex_page_t page;
    err = model.page(request, nullptr, page);
    require(err.ok() && page.rows.size() == 2,
            "hex patch projection page must contain both affected rows");
    require(page.rows[0].overlays.size() == 1 &&
                page.rows[0].overlays[0].address == 14 &&
                page.rows[0].overlays[0].extent == 2 &&
                page.rows[0].overlays[0].patch_bytes == std::vector<std::uint8_t>({0xAA, 0xBB}),
            "hex first-row projection must clip patch address, extent, and bytes");
    require(page.rows[1].overlays.size() == 1 &&
                page.rows[1].overlays[0].address == 16 &&
                page.rows[1].overlays[0].extent == 4 &&
                page.rows[1].overlays[0].patch_bytes ==
                    std::vector<std::uint8_t>({0xCC, 0xDD, 0xEE, 0x41}),
            "hex second-row projection must carry the remaining patch bytes");
    require(page.rows[0].bytes[14] == 0xAA && page.rows[0].bytes[15] == 0xBB,
            "hex first row must apply projected patch content");
    require(page.rows[1].bytes[0] == 0xCC && page.rows[1].bytes[3] == 0x41,
            "hex second row must apply projected patch content");
    require(page.rows[0].hex_text.substr(page.rows[0].hex_text.size() - 5) == "AA BB",
            "hex rendered text must expose patched bytes");
    require(page.rows[1].ascii_text == "...A............",
            "hex ASCII projection must reflect patched printable content");

    auto copied_page = page;
    page = {};
    require(copied_page.rows[1].overlays[0].patch_bytes[3] == 0x41,
            "hex copied page must retain owned overlay projections");

    auto invalid_patch = patch;
    invalid_patch.extent = 7;
    err = model.apply_overlay(model.bound_generation(), invalid_patch);
    require(err.code == hex_document::hex_error_code_t::invalid_argument,
            "hex patch extent must exactly match patch content");

    hex_document::hex_selection_t invalid_address;
    invalid_address.kind = selection_kind_t::address;
    invalid_address.address = 1;
    err = model.select(invalid_address, model.bound_generation());
    require(err.code == hex_document::hex_error_code_t::selection_rejected,
            "hex address selection must require has_address");

    hex_document::hex_selection_t mismatched_row;
    mismatched_row.kind = selection_kind_t::address;
    mismatched_row.has_address = true;
    mismatched_row.address = 1;
    mismatched_row.start_row = {2};
    mismatched_row.end_row = {2};
    err = model.select(mismatched_row, model.bound_generation());
    require(err.code == hex_document::hex_error_code_t::selection_rejected,
            "hex selection must reject a row id that does not contain the address");

    hex_document::hex_selection_t range;
    range.kind = selection_kind_t::range;
    range.has_address = true;
    range.address = 14;
    range.extent = 6;
    err = model.select(range, model.bound_generation());
    require(err.ok() && model.selection().start_row.value == 1 &&
                model.selection().end_row.value == 2,
            "hex range selection must canonicalize rows across an interior boundary");

    range.address = (std::numeric_limits<std::uint64_t>::max)();
    range.extent = 2;
    err = model.select(range, model.bound_generation());
    require(err.code == hex_document::hex_error_code_t::selection_rejected,
            "hex range selection must reject address overflow");

    hex_source_t oversized(hex_document::k_hex_document_max_total_rows + 1);
    hex_document::hex_document_model_t oversized_model(oversized);
    require(oversized_model.total_rows() == hex_document::k_hex_document_max_total_rows,
            "hex total_rows must remain capped at the document ceiling");
    request.limit = hex_document::k_hex_document_max_page_size + 1;
    err = oversized_model.page(request, nullptr, page);
    require(err.code == hex_document::hex_error_code_t::invalid_page,
            "hex page must reject a request above the packed-page ceiling");
    request.limit = 1;
    err = oversized_model.page(request, nullptr, page);
    require(err.code == hex_document::hex_error_code_t::resource_exhausted,
            "hex page must reject a source above the row ceiling");

    hex_source_t exact(hex_document::k_hex_document_max_total_rows);
    hex_document::hex_document_model_t exact_model(exact);
    request.offset = hex_document::k_hex_document_max_total_rows - 1;
    err = exact_model.page(request, nullptr, page);
    require(err.ok() && page.rows.size() == 1 &&
                page.rows.front().id.value == hex_document::k_hex_document_max_total_rows,
            "hex row ceiling must remain addressable without overflow");
}

void verify_hex_cross_document_navigation()
{
    hex_source_t source(1000);
    hex_nav_t nav;
    hex_document::hex_document_model_t model(source, nullptr, &nav);

    hex_document::hex_cross_document_request_t req;
    req.target = hex_document::hex_cross_document_target_t::disassembly;
    req.address = 0x200;
    req.source_document.kind = document_kind_t::hex;
    req.source_document.workspace = {1};
    req.source_document.object_id = 2;

    hex_document::hex_cross_document_result_t result;
    auto err = model.cross_document(req, result);
    require(err.ok() && result.resolved, "hex cross-document navigation must succeed");
    require(result.target_document.kind == document_kind_t::disassembly,
            "hex cross-document target must be disassembly");
}

void verify_independent_workspace_fixtures()
{
    disasm_source_t source_a(1000);
    disasm_source_t source_b(2000);

    disasm_document::disasm_document_model_t model_a(source_a);
    disasm_document::disasm_document_model_t model_b(source_b);

    require(model_a.total_rows() == 1000, "workspace A disasm must have 1000 rows");
    require(model_b.total_rows() == 2000, "workspace B disasm must have 2000 rows");

    source_a.advance_generation();
    require(model_a.is_stale(), "workspace A must be stale after source advance");
    require(!model_b.is_stale(), "workspace B must not be affected by workspace A advance");

    disasm_document::disasm_selection_t sel;
    sel.kind = selection_kind_t::address;
    sel.has_address = true;
    sel.address = 0x401000U;
    auto err = model_a.select(sel, model_a.bound_generation());
    require(err.code == disasm_document::disasm_error_code_t::stale_generation,
            "workspace A select on stale generation must return stale error");

    err = model_b.select(sel, model_b.bound_generation());
    require(err.ok(), "workspace B select must succeed independently");

    hex_source_t hex_a(500);
    hex_source_t hex_b(800);
    hex_document::hex_document_model_t hex_model_a(hex_a);
    hex_document::hex_document_model_t hex_model_b(hex_b);

    require(hex_model_a.total_rows() == 500, "workspace A hex must have 500 rows");
    require(hex_model_b.total_rows() == 800, "workspace B hex must have 800 rows");
    require(hex_model_a.bound_generation() == hex_model_b.bound_generation(),
            "independent hex models may share generation number");
    hex_a.advance_generation();
    require(hex_model_a.is_stale(), "workspace A hex must be stale");
    require(!hex_model_b.is_stale(), "workspace B hex must not be stale");
}

aida::analysis::address_t pseudocode_address(std::uint64_t value)
{
    aida::analysis::address_t address;
    address.space = aida::analysis::address_space_id_t::relative_virtual;
    address.value = value;
    address.architecture = aida::analysis::architecture_id_t::x86_64;
    address.mode = aida::analysis::architecture_mode_t::x86_64;
    return address;
}

aida::analysis::decompiler_entity_key_t pseudocode_entity()
{
    aida::analysis::native_decompiler_entity_identity_t identity;
    identity.function_id = 1;
    identity.entry = pseudocode_address(0x401000);
    identity.end = pseudocode_address(0x401100);
    identity.function_bytes_hash =
        aida::analysis::stable_serialization_hash(std::string("workbench-function"));
    identity.canonical_symbol = "fixture::main";

    aida::analysis::decompiler_entity_key_t entity;
    entity.kind = aida::analysis::decompiler_entity_kind_t::native_function;
    entity.format = aida::analysis::format_id_t::pe32_plus;
    entity.architecture = aida::analysis::architecture_id_t::x86_64;
    entity.mode = aida::analysis::architecture_mode_t::x86_64;
    entity.identity = std::move(identity);
    return entity;
}

class pseudo_source_t final : public pseudocode_document::pseudocode_source_adapter_t {
public:
    pseudo_source_t() = default;

    void advance_generation() { ++generation_; }
    void set_fail_next(bool value) { fail_next_ = value; }

    std::uint64_t current_generation() const noexcept override { return generation_; }
    bool generation_current(std::uint64_t gen) const noexcept override
    {
        return gen == generation_;
    }

    workbench_error_t request_decompilation(
        const pseudocode_document::pseudocode_request_t& request,
        std::uint64_t job_id) override
    {
        if (fail_next_) {
            fail_next_ = false;
            return {workbench_error_code_t::adapter_rejected, job_id};
        }
        jobs_.push_back({job_id, job_state_t::pending, request, {}, {}});
        return {};
    }

    workbench_error_t cancel_decompilation(std::uint64_t job_id) override
    {
        const auto job = find_job(job_id);
        if (job == jobs_.end() || job->state != job_state_t::pending)
            return {workbench_error_code_t::invalid_document_state, job_id};
        jobs_.erase(job);
        return {};
    }

    bool poll_result(std::uint64_t job_id,
                     aida::analysis::decompiler_document_t& output) override
    {
        const auto job = find_job(job_id);
        if (job == jobs_.end() || job->state != job_state_t::result_ready)
            return false;
        output = std::move(job->document);
        jobs_.erase(job);
        return true;
    }

    bool poll_failure(std::uint64_t job_id,
                      std::vector<aida::analysis::decompiler_diagnostic_t>& output) override
    {
        const auto job = find_job(job_id);
        if (job == jobs_.end() || job->state != job_state_t::failure_ready)
            return false;
        output = std::move(job->diagnostics);
        jobs_.erase(job);
        return true;
    }

    bool job_active(std::uint64_t job_id) const noexcept override
    {
        const auto job = find_job(job_id);
        return job != jobs_.end() && job->state == job_state_t::pending;
    }

    aida::analysis::decompiler_profile_budget_t profile_budget(
        aida::analysis::decompiler_profile_id_t profile) const noexcept override
    {
        aida::analysis::decompiler_profile_budget_t budget;
        budget.profile = profile;
        budget.max_wall_clock_ms = 30000;
        budget.max_cpu_ms = 30000;
        budget.max_memory_bytes = 1ULL << 30;
        budget.max_provider_ir_nodes = 1ULL << 20;
        budget.max_hir_nodes = 1ULL << 20;
        budget.max_ast_nodes = 1ULL << 20;
        if (profile == aida::analysis::decompiler_profile_id_t::thorough) {
            budget.max_semantic_queries = 100;
            budget.semantic_proofs_enabled = true;
        }
        return budget;
    }

    bool complete_success(std::uint64_t job_id)
    {
        const auto job = find_job(job_id);
        if (job == jobs_.end() || job->state != job_state_t::pending)
            return false;
        job->document = make_document(job->request);
        job->state = job_state_t::result_ready;
        return true;
    }

    bool complete_failure(std::uint64_t job_id)
    {
        const auto job = find_job(job_id);
        if (job == jobs_.end() || job->state != job_state_t::pending)
            return false;
        aida::analysis::decompiler_diagnostic_t diagnostic;
        diagnostic.severity = aida::analysis::decompiler_diagnostic_severity_t::error;
        diagnostic.code = aida::analysis::decompiler_diagnostic_code_t::provider_failure;
        diagnostic.localization_key = "decompiler.worker.provider_failure";
        diagnostic.localization_arguments = {"synthetic_failure"};
        diagnostic.retryable = true;
        diagnostic.ordinal = 1;
        job->diagnostics.push_back(std::move(diagnostic));
        job->state = job_state_t::failure_ready;
        return true;
    }

private:
    enum class job_state_t : std::uint8_t {
        pending,
        result_ready,
        failure_ready
    };

    struct job_t {
        std::uint64_t id = 0;
        job_state_t state = job_state_t::pending;
        pseudocode_document::pseudocode_request_t request;
        aida::analysis::decompiler_document_t document;
        std::vector<aida::analysis::decompiler_diagnostic_t> diagnostics;
    };

    static aida::analysis::decompiler_document_t make_document(
        const pseudocode_document::pseudocode_request_t& request)
    {
        const auto make_coordinate = [&request](
            aida::analysis::decompiler_coordinate_layer_t layer,
            std::uint64_t begin,
            std::uint64_t end) {
            aida::analysis::source_coordinate_t coordinate;
            coordinate.layer = layer;
            coordinate.workspace_generation = request.workspace_generation;
            coordinate.entity = request.entity;
            coordinate.address_range = aida::analysis::decompiler_address_range_t{
                pseudocode_address(begin), pseudocode_address(end)};
            return coordinate;
        };

        aida::analysis::typed_pseudocode_ast_node_t root;
        root.id = 1;
        root.kind = aida::analysis::typed_pseudocode_ast_node_kind_t::function_definition;
        root.child_ids = {2};
        root.stable_text = "main";
        root.coordinate = make_coordinate(
            aida::analysis::decompiler_coordinate_layer_t::typed_ast,
            0x401000, 0x401008);
        root.confidence = 100;

        aida::analysis::typed_pseudocode_ast_node_t body;
        body.id = 2;
        body.kind = aida::analysis::typed_pseudocode_ast_node_kind_t::compound_statement;
        body.child_ids = {3};
        body.coordinate = root.coordinate;
        body.confidence = 100;

        aida::analysis::typed_pseudocode_ast_node_t statement;
        statement.id = 3;
        statement.kind = aida::analysis::typed_pseudocode_ast_node_kind_t::return_statement;
        statement.stable_text = "return 0";
        statement.coordinate = root.coordinate;
        statement.confidence = 100;

        aida::analysis::typed_pseudocode_ast_v2_t ast;
        ast.entity = request.entity;
        ast.hir_hash = aida::analysis::stable_serialization_hash(
            std::string("workbench-hir"));
        ast.type_graph_hash = aida::analysis::stable_serialization_hash(
            std::string("workbench-types"));
        ast.root_node_id = 1;
        ast.body_node_id = 2;
        ast.nodes = {std::move(root), std::move(body), std::move(statement)};

        aida::analysis::decompiler_document_t document;
        document.schema_version = aida::analysis::k_decompiler_document_schema_version;
        document.entity = request.entity;
        document.ast = std::move(ast);
        document.ast_hash = aida::analysis::stable_serialization_hash(document.ast);
        document.type_graph_hash = document.ast.type_graph_hash;
        document.profile = request.profile;
        document.renderer.style_id = "aida.c03.workbench";
        document.rendered_text = "int main() {\n  return 0;\n}\n";

        const auto append_token = [&document](
            aida::analysis::decompiler_document_token_kind_t kind,
            std::uint32_t begin, std::uint32_t end,
            std::uint64_t ast_node_id) {
            aida::analysis::decompiler_document_token_t token;
            token.kind = kind;
            token.range.begin = begin;
            token.range.end = end;
            token.ast_node_id = ast_node_id;
            document.tokens.push_back(token);
        };
        using token_kind_t = aida::analysis::decompiler_document_token_kind_t;
        append_token(token_kind_t::keyword, 0, 3, 1);
        append_token(token_kind_t::whitespace, 3, 4, 1);
        append_token(token_kind_t::identifier, 4, 8, 1);
        append_token(token_kind_t::punctuation, 8, 10, 1);
        append_token(token_kind_t::whitespace, 10, 11, 1);
        append_token(token_kind_t::punctuation, 11, 12, 1);
        append_token(token_kind_t::whitespace, 12, 13, 2);
        append_token(token_kind_t::whitespace, 13, 15, 2);
        append_token(token_kind_t::keyword, 15, 21, 3);
        append_token(token_kind_t::whitespace, 21, 22, 3);
        append_token(token_kind_t::literal, 22, 23, 3);
        append_token(token_kind_t::punctuation, 23, 24, 3);
        append_token(token_kind_t::whitespace, 24, 25, 2);
        append_token(token_kind_t::punctuation, 25, 26, 2);
        append_token(token_kind_t::whitespace, 26, 27, 1);

        auto coordinate = make_coordinate(
            aida::analysis::decompiler_coordinate_layer_t::document,
            0x401004, 0x401008);
        coordinate.document_range = aida::analysis::decompiler_token_range_t{15, 21};
        aida::analysis::decompiler_source_origin_t source_origin;
        source_origin.source_artifact_hash = aida::analysis::stable_serialization_hash(
            std::string("fixture-source"));
        source_origin.source_path = "fixture.c";
        source_origin.first_line = 42;
        source_origin.first_column = 3;
        source_origin.last_line = 42;
        source_origin.last_column = 9;
        coordinate.source_origin = source_origin;

        aida::analysis::decompiler_document_source_map_t source_map;
        source_map.document_range = *coordinate.document_range;
        source_map.coordinates.push_back(coordinate);
        document.source_maps.push_back(std::move(source_map));

        aida::analysis::decompiler_diagnostic_t diagnostic;
        diagnostic.severity = aida::analysis::decompiler_diagnostic_severity_t::warning;
        diagnostic.code = aida::analysis::decompiler_diagnostic_code_t::unresolved_type;
        diagnostic.localization_key = "decompiler.warning.unresolved_type";
        diagnostic.localization_arguments = {"result"};
        diagnostic.coordinate = std::move(coordinate);
        diagnostic.confidence = 80;
        diagnostic.ordinal = 1;
        document.diagnostics.push_back(std::move(diagnostic));
        return document;
    }

    std::vector<job_t>::iterator find_job(std::uint64_t job_id)
    {
        return std::find_if(jobs_.begin(), jobs_.end(),
            [job_id](const job_t& job) { return job.id == job_id; });
    }

    std::vector<job_t>::const_iterator find_job(std::uint64_t job_id) const noexcept
    {
        return std::find_if(jobs_.begin(), jobs_.end(),
            [job_id](const job_t& job) { return job.id == job_id; });
    }

    std::uint64_t generation_ = 1;
    bool fail_next_ = false;
    std::vector<job_t> jobs_;
};

void verify_pseudocode_explicit_request_only()
{
    pseudo_source_t source;
    pseudocode_document::pseudocode_document_model_t model(source);

    require(model.cache_state() == pseudocode_document::pseudocode_cache_state_t::empty,
            "pseudocode cache must start empty");

    require(model.cached_document_count() == 0,
            "pseudocode must not auto-request decompilation");

    pseudocode_document::pseudocode_page_request_t page_req;
    page_req.first_line = 0;
    page_req.line_count = 10;
    pseudocode_document::pseudocode_page_t page;
    auto err = model.page(page_req, page);
    require(!err.ok(), "pseudocode page without request must fail with cache miss");
    require(err.code == pseudocode_document::pseudocode_error_code_t::cache_miss,
            "pseudocode page before request must return cache_miss");
}

void verify_pseudocode_request_and_cache()
{
    pseudo_source_t source;
    pseudocode_document::pseudocode_document_model_t model(source);

    pseudocode_document::pseudocode_request_t req;
    req.entity = pseudocode_entity();
    req.profile = aida::analysis::decompiler_profile_id_t::fast;
    req.workspace_generation = model.current_generation();
    req.timeout_ms = 5000;

    auto err = model.request(req);
    require(err.ok(), "pseudocode request must succeed");
    require(model.cache_state() == pseudocode_document::pseudocode_cache_state_t::requesting,
            "pseudocode cache must be requesting after explicit request");

    const auto cached = model.cached_document();
    require(cached != nullptr, "pseudocode active document must exist after request");
    const auto job_id = cached->job_id;

    require(source.job_active(job_id), "pseudocode source must show job as active");

    require(source.complete_success(job_id), "pseudocode fake worker must complete active job");

    err = model.poll(job_id);
    require(err.ok(), "pseudocode poll must succeed when result is ready");
    require(model.cache_state() == pseudocode_document::pseudocode_cache_state_t::cached,
            "pseudocode cache must be cached after successful poll");

    pseudocode_document::pseudocode_page_request_t page_req;
    page_req.first_line = 0;
    page_req.line_count = 10;
    pseudocode_document::pseudocode_page_t page;
    err = model.page(page_req, page);
    require(err.ok(), "pseudocode page must succeed after cache");
    require(page.total_lines == 3, "pseudocode must split rendered text into 3 lines");
    require(page.lines.size() == 3, "pseudocode page must return 3 lines");
    require(model.profile_info().profile == aida::analysis::decompiler_profile_id_t::fast,
            "pseudocode profile presentation must retain the requested profile");
    require(model.profile_info().max_wall_clock_ms == 30000 &&
                model.profile_info().max_cpu_ms == 30000 &&
                model.profile_info().max_memory_bytes == (1ULL << 30),
            "pseudocode profile presentation must retain worker budgets");
}

void verify_pseudocode_tokens_diagnostics_and_mapping()
{
    pseudo_source_t source;
    pseudocode_document::pseudocode_document_model_t model(source);

    pseudocode_document::pseudocode_request_t request;
    request.entity = pseudocode_entity();
    request.workspace_generation = model.current_generation();
    auto err = model.request(request);
    require(err.ok(), "pseudocode typed presentation request must succeed");
    const auto job_id = model.cached_document()->job_id;
    require(source.complete_success(job_id),
            "pseudocode typed presentation worker must complete");
    err = model.poll(job_id);
    require(err.ok(), "pseudocode typed presentation result must be accepted");

    pseudocode_document::pseudocode_page_request_t page_request;
    pseudocode_document::pseudocode_page_t page;
    page_request.line_count = pseudocode_document::k_pseudocode_document_max_page_lines + 1;
    err = model.page(page_request, page);
    require(err.code == pseudocode_document::pseudocode_error_code_t::invalid_argument,
            "pseudocode page must reject a request above the line-page ceiling");
    page_request.line_count = 10;
    err = model.page(page_request, page);
    require(err.ok(), "pseudocode typed presentation page must succeed");
    require(page.tokens.size() == 15,
            "pseudocode page must expose every typed document token");
    require(page.tokens[0].text == "int" && page.tokens[2].text == "main" &&
                page.tokens[8].text == "return" && page.tokens[10].text == "0",
            "pseudocode token presentation must preserve rendered token text");
    require(page.tokens[0].kind ==
                aida::analysis::decompiler_document_token_kind_t::keyword &&
                page.tokens[2].kind ==
                    aida::analysis::decompiler_document_token_kind_t::identifier &&
                page.tokens[10].kind ==
                    aida::analysis::decompiler_document_token_kind_t::literal,
            "pseudocode token presentation must preserve typed token kinds");
    require(page.lines[0].first_token == 0 && page.lines[0].token_count == 7 &&
                page.lines[1].first_token == 7 && page.lines[1].token_count == 6 &&
                page.lines[2].first_token == 13 && page.lines[2].token_count == 2,
            "pseudocode line presentation must index tokens by token ordinal");
    require(page.source_maps.size() == 1 && page.source_maps[0].has_address &&
                page.source_maps[0].address == 0x401004 &&
                page.source_maps[0].address_extent == 4 &&
                page.source_maps[0].has_source &&
                page.source_maps[0].source_path == "fixture.c" &&
                page.source_maps[0].source_line == 42,
            "pseudocode page must expose typed address and source mappings");
    require(page.diagnostics.size() == 1 &&
                page.diagnostics[0].severity ==
                    aida::analysis::decompiler_diagnostic_severity_t::warning &&
                page.diagnostics[0].message ==
                    "decompiler.warning.unresolved_type result" &&
                page.diagnostics[0].has_line && page.diagnostics[0].line == 42,
            "pseudocode diagnostics must include presentation messages and source lines");

    pseudocode_document::pseudocode_address_map_entry_t mapping;
    err = model.resolve_address(0x401006, mapping);
    require(err.ok() && mapping.address == 0x401004 && mapping.extent == 4 &&
                mapping.token_begin == 15 && mapping.token_end == 21 &&
                mapping.line_number == 2,
            "pseudocode interior address must resolve to its containing token range");
    err = model.resolve_token(17, mapping);
    require(err.ok() && mapping.address == 0x401004,
            "pseudocode interior token offset must resolve to its address range");
    err = model.resolve_address(0x401008, mapping);
    require(err.code == pseudocode_document::pseudocode_error_code_t::address_not_mapped,
            "pseudocode address range end must remain exclusive");

    pseudocode_document::pseudocode_selection_t selection;
    selection.kind = selection_kind_t::address;
    selection.has_address = true;
    selection.address = 0x401007;
    err = model.select(selection);
    require(err.ok() && model.selection().token_begin == 15 &&
                model.selection().token_end == 21 &&
                model.selection().line_number == 2,
            "pseudocode address selection must canonicalize token and line coordinates");

    auto copied_page = page;
    source.advance_generation();
    model.refresh();
    page = {};
    require(copied_page.tokens[8].text == "return" &&
                copied_page.source_maps[0].source_path == "fixture.c" &&
                copied_page.diagnostics[0].message ==
                    "decompiler.warning.unresolved_type result",
            "pseudocode page presentation strings must own their storage");
}

void verify_pseudocode_cancellation()
{
    pseudo_source_t source;
    pseudocode_document::pseudocode_document_model_t model(source);

    pseudocode_document::pseudocode_request_t req;
    req.entity = pseudocode_entity();
    req.workspace_generation = model.current_generation();
    auto err = model.request(req);
    require(err.ok(), "pseudocode request for cancellation test must succeed");

    const auto job_id = model.cached_document()->job_id;
    err = model.cancel(job_id);
    require(err.ok(), "pseudocode cancel must succeed for active job");
    require(model.cache_state() == pseudocode_document::pseudocode_cache_state_t::cancelled,
            "pseudocode cache must be cancelled after cancel");

    err = model.cancel(job_id);
    require(!err.ok(), "pseudocode cancel of already-cancelled job must fail");
}

void verify_pseudocode_stale_result()
{
    pseudo_source_t source;
    pseudocode_document::pseudocode_document_model_t model(source);

    pseudocode_document::pseudocode_request_t req;
    req.entity = pseudocode_entity();
    req.workspace_generation = model.current_generation();
    auto err = model.request(req);
    require(err.ok(), "pseudocode request for stale test must succeed");
    const auto job_id = model.cached_document()->job_id;

    source.advance_generation();
    require(source.complete_success(job_id), "pseudocode fake worker must publish stale result");
    err = model.poll(job_id);
    require(err.code == pseudocode_document::pseudocode_error_code_t::stale_result,
            "pseudocode poll must reject a generation-stale worker result");
    require(model.cache_state() == pseudocode_document::pseudocode_cache_state_t::stale,
            "pseudocode stale result must leave the cache stale");
    require(model.cached_document()->document == nullptr,
            "pseudocode stale result must not be cached");

    model.refresh();
    req.workspace_generation = model.current_generation();
    err = model.request(req);
    require(err.ok(), "pseudocode request for stale failure test must succeed");
    const auto failure_job_id = model.cached_document()->job_id;
    source.advance_generation();
    require(source.complete_failure(failure_job_id),
            "pseudocode fake worker must publish stale failure result");
    err = model.poll(failure_job_id);
    require(err.code == pseudocode_document::pseudocode_error_code_t::stale_result,
            "pseudocode poll must reject generation-stale failure diagnostics");
    require(model.cache_state() == pseudocode_document::pseudocode_cache_state_t::stale,
            "pseudocode stale failure must leave the cache stale");
    require(model.diagnostics().empty(),
            "pseudocode stale failure diagnostics must not leak into presentation state");
}

void verify_pseudocode_worker_failure()
{
    pseudo_source_t source;
    pseudocode_document::pseudocode_document_model_t model(source);

    pseudocode_document::pseudocode_request_t req;
    req.entity = pseudocode_entity();
    req.workspace_generation = model.current_generation();
    auto err = model.request(req);
    require(err.ok(), "pseudocode failure fixture request must succeed");
    const auto job_id = model.cached_document()->job_id;
    require(source.complete_failure(job_id), "pseudocode fake worker must publish failure");
    err = model.poll(job_id);
    require(err.code == pseudocode_document::pseudocode_error_code_t::worker_failure,
            "pseudocode worker failure must return worker_failure");
    require(model.cache_state() == pseudocode_document::pseudocode_cache_state_t::failed,
            "pseudocode worker failure must set failed cache state");
    const auto diagnostics = model.diagnostics();
    require(diagnostics.size() == 1, "pseudocode worker failure must expose its diagnostic");
    require(diagnostics.front().message ==
                "decompiler.worker.provider_failure synthetic_failure",
            "pseudocode worker failure diagnostic must include a presentation message");

    pseudo_source_t rejecting_source;
    rejecting_source.set_fail_next(true);
    pseudocode_document::pseudocode_document_model_t rejecting_model(rejecting_source);
    req.workspace_generation = rejecting_model.current_generation();
    err = rejecting_model.request(req);
    require(err.code == pseudocode_document::pseudocode_error_code_t::adapter_rejected,
            "pseudocode request submission failure must return adapter_rejected");
}

void verify_pseudocode_multi_workspace()
{
    pseudo_source_t source_a;
    pseudo_source_t source_b;
    pseudocode_document::pseudocode_document_model_t model_a(source_a);
    pseudocode_document::pseudocode_document_model_t model_b(source_b);

    pseudocode_document::pseudocode_request_t req;
    req.entity = pseudocode_entity();
    req.workspace_generation = model_a.current_generation();
    auto err = model_a.request(req);
    require(err.ok(), "workspace A pseudocode request must succeed");

    req.workspace_generation = model_b.current_generation();
    err = model_b.request(req);
    require(err.ok(), "workspace B pseudocode request must succeed");

    source_a.advance_generation();
    require(model_a.is_stale(), "workspace A pseudocode must be stale");
    require(!model_b.is_stale(), "workspace B pseudocode must not be stale");

    req.workspace_generation = source_a.current_generation();
    err = model_a.request(req);
    require(err.code == pseudocode_document::pseudocode_error_code_t::stale_generation,
            "pseudocode stale model must reject the source's newer generation before refresh");
}

class graph_source_t final : public graph_document::graph_source_adapter_t {
public:
    graph_source_t(std::uint64_t node_count, std::uint64_t edge_count)
    {
        generation_data_t gen_data;
        gen_data.node_count = node_count;
        gen_data.edge_count = edge_count;
        generations_.push_back(gen_data);
        rebuild();
    }

    void advance_generation()
    {
        generation_data_t gen_data = generations_.back();
        gen_data.node_count += 2;
        gen_data.edge_count += 1;
        generations_.push_back(gen_data);
        ++generation_;
        rebuild();
    }

    void enable_parallel_edges() noexcept { parallel_edges_ = true; }

    std::uint64_t current_generation() const noexcept override { return generation_; }
    bool generation_current(std::uint64_t gen) const noexcept override
    {
        return gen == generation_;
    }
    bool generation_available(std::uint64_t gen) const noexcept override
    {
        return gen != 0 && gen <= generation_;
    }
    bool supports_kind(graph_document::graph_kind_t kind) const noexcept override
    {
        return kind == graph_document::graph_kind_t::cfg;
    }

    std::uint64_t node_count(std::uint64_t gen, graph_document::graph_kind_t,
                             std::uint64_t) const noexcept override
    {
        if (gen == 0 || gen > generation_)
            return 0;
        return generations_[gen - 1].node_count;
    }

    std::uint64_t edge_count(std::uint64_t gen, graph_document::graph_kind_t,
                             std::uint64_t) const noexcept override
    {
        if (gen == 0 || gen > generation_)
            return 0;
        return generations_[gen - 1].edge_count;
    }

    bool node_at(std::uint64_t gen, graph_document::graph_kind_t,
                 std::uint64_t, std::uint64_t ordinal,
                 graph_document::graph_node_view_t& output) const noexcept override
    {
        if (gen == 0 || gen > generation_)
            return false;
        const auto nc = generations_[gen - 1].node_count;
        if (ordinal >= nc)
            return false;
        output.id = graph_document::compute_deterministic_node_id(0x500000U + ordinal * 0x10);
        output.kind = graph_document::graph_node_kind_t::basic_block;
        output.address = 0x500000U + ordinal * 0x10;
        output.label = labels_[ordinal % labels_.size()];
        output.instruction_count = 5;
        output.in_degree = ordinal > 0 ? 1 : 0;
        output.out_degree = ordinal < nc - 1 ? 1 : 0;
        return true;
    }

    bool edge_at(std::uint64_t gen, graph_document::graph_kind_t,
                 std::uint64_t, std::uint64_t ordinal,
                 graph_document::graph_edge_view_t& output) const noexcept override
    {
        if (gen == 0 || gen > generation_)
            return false;
        const auto ec = generations_[gen - 1].edge_count;
        if (ordinal >= ec)
            return false;
        const auto edge_ordinal = parallel_edges_ && ordinal < 2 ? 0 : ordinal;
        const auto src = graph_document::compute_deterministic_node_id(
            0x500000U + edge_ordinal * 0x10);
        const auto tgt = graph_document::compute_deterministic_node_id(
            0x500000U + (edge_ordinal + 1) * 0x10);
        output.source = src;
        output.target = tgt;
        output.kind = graph_document::graph_edge_kind_t::unconditional;
        output.site_address = 0x500000U + edge_ordinal * 0x10 + 4;
        output.parallel_ordinal = parallel_edges_ && ordinal < 2 ? ordinal : 0;
        output.id = graph_document::compute_deterministic_edge_id(
            {output.source, output.target, output.kind, output.site_address,
             output.parallel_ordinal});
        output.label = "edge_" + std::to_string(ordinal);
        return true;
    }

    bool node_by_address(std::uint64_t gen, graph_document::graph_kind_t kind,
                         std::uint64_t func_addr, std::uint64_t address,
                         graph_document::graph_node_view_t& output,
                         std::uint64_t& ordinal) const noexcept override
    {
        if (gen == 0 || gen > generation_)
            return false;
        if (address < 0x500000U)
            return false;
        const auto offset = address - 0x500000U;
        if (offset % 0x10 != 0)
            return false;
        ordinal = offset / 0x10;
        return node_at(gen, kind, func_addr, ordinal, output);
    }

    bool node_by_id(std::uint64_t gen, graph_document::graph_kind_t kind,
                    std::uint64_t func_addr,
                    graph_document::graph_node_id_t id,
                    graph_document::graph_node_view_t& output,
                    std::uint64_t& ordinal) const noexcept override
    {
        const auto count = node_count(gen, kind, func_addr);
        for (std::uint64_t index = 0; index < count; ++index) {
            graph_document::graph_node_view_t candidate;
            if (!node_at(gen, kind, func_addr, index, candidate))
                return false;
            if (candidate.id == id) {
                output = std::move(candidate);
                ordinal = index;
                return true;
            }
        }
        return false;
    }

    bool edge_by_id(std::uint64_t gen, graph_document::graph_kind_t kind,
                    std::uint64_t func_addr,
                    graph_document::graph_edge_id_t id,
                    graph_document::graph_edge_view_t& output,
                    std::uint64_t& ordinal) const noexcept override
    {
        const auto count = edge_count(gen, kind, func_addr);
        for (std::uint64_t index = 0; index < count; ++index) {
            graph_document::graph_edge_view_t candidate;
            if (!edge_at(gen, kind, func_addr, index, candidate))
                return false;
            if (candidate.id == id) {
                output = std::move(candidate);
                ordinal = index;
                return true;
            }
        }
        return false;
    }

private:
    struct generation_data_t {
        std::uint64_t node_count = 0;
        std::uint64_t edge_count = 0;
    };

    void rebuild()
    {
        labels_.clear();
        labels_ = {"bb_0", "bb_1", "bb_2", "bb_3", "bb_4",
                   "bb_5", "bb_6", "bb_7", "bb_8", "bb_9"};
    }

    std::uint64_t generation_ = 1;
    bool parallel_edges_ = false;
    std::vector<generation_data_t> generations_;
    std::vector<std::string> labels_;
};

class graph_overlay_t final : public graph_document::graph_overlay_adapter_t {
public:
    void set(graph_document::graph_node_id_t node, std::string text)
    {
        entries_.emplace_back(node, std::move(text));
    }

    void set_reported_count(std::uint32_t count) noexcept
    {
        reported_count_ = count;
    }

    std::uint32_t overlay_count(std::uint64_t) const noexcept override
    {
        return reported_count_ != 0 ? reported_count_
                                    : static_cast<std::uint32_t>(entries_.size());
    }

    bool overlay_node(std::uint64_t, graph_document::graph_node_id_t node,
                      std::string& text) const noexcept override
    {
        for (const auto& entry : entries_) {
            if (entry.first == node) {
                text = entry.second;
                return true;
            }
        }
        return false;
    }

private:
    std::uint32_t reported_count_ = 0;
    std::vector<std::pair<graph_document::graph_node_id_t, std::string>> entries_;
};

class graph_phase_cancellation_t final
    : public graph_document::graph_layout_cancellation_t {
public:
    explicit graph_phase_cancellation_t(std::uint64_t trigger) noexcept
        : trigger_(trigger)
    {
    }

    bool cancelled() const noexcept override
    {
        ++checks_;
        return checks_ >= trigger_;
    }

    std::uint64_t checks() const noexcept { return checks_; }

private:
    std::uint64_t trigger_ = 0;
    mutable std::uint64_t checks_ = 0;
};

void verify_graph_large_cap()
{
    graph_source_t source(100, 99);
    graph_document::graph_document_model_t model(source);

    require(model.node_count(graph_document::graph_kind_t::cfg, 0) == 100,
            "graph model node count must match source");

    graph_document::graph_layout_request_t layout_req;
    layout_req.expected_generation = model.bound_generation();
    layout_req.max_nodes = 50;
    layout_req.max_iterations = 100;
    layout_req.canvas_width = 1024.0f;
    layout_req.canvas_height = 768.0f;

    graph_document::graph_layout_t layout;
    auto err = model.compute_layout(layout_req, nullptr, layout);
    require(err.code == graph_document::graph_error_code_t::layout_capacity,
            "graph layout exceeding max_nodes must return layout_capacity");
    require(!layout.complete, "graph layout must not be complete when over capacity");

    layout_req.max_nodes = 200;
    err = model.compute_layout(layout_req, nullptr, layout);
    require(err.ok(), "graph layout within max_nodes must succeed");
    require(layout.complete, "graph layout must be complete");
    require(layout.nodes.size() == 100, "graph layout must position all nodes");

    graph_source_t layout_edge_source(
        2, graph_document::k_graph_document_max_layout_edges + 1ULL);
    graph_document::graph_document_model_t layout_edge_model(layout_edge_source);
    layout_req.expected_generation = layout_edge_model.bound_generation();
    layout_req.max_nodes = 2;
    layout_req.max_edges = graph_document::k_graph_document_max_layout_edges;
    err = layout_edge_model.compute_layout(layout_req, nullptr, layout);
    require(err.code == graph_document::graph_error_code_t::layout_capacity,
            "graph layout exceeding max_edges must return layout_capacity");

    graph_source_t global_edge_source(
        2, graph_document::k_graph_document_max_edges + 1ULL);
    graph_document::graph_document_model_t global_edge_model(global_edge_source);
    layout_req.expected_generation = global_edge_model.bound_generation();
    err = global_edge_model.compute_layout(layout_req, nullptr, layout);
    require(err.code == graph_document::graph_error_code_t::graph_too_large,
            "graph layout exceeding the global edge cap must return graph_too_large");

    graph_document::graph_page_request_t page_request;
    page_request.limit = 1;
    page_request.edges = true;
    graph_document::graph_page_t page;
    err = global_edge_model.page(page_request, nullptr, page);
    require(err.code == graph_document::graph_error_code_t::graph_too_large,
            "graph edge paging must enforce the global edge cap");

    const auto old_generation = global_edge_source.current_generation();
    global_edge_source.advance_generation();
    graph_document::graph_document_model_t current_edge_model(global_edge_source);
    graph_document::graph_diff_result_t diff;
    err = current_edge_model.diff_generations(
        old_generation, global_edge_source.current_generation(),
        graph_document::graph_kind_t::cfg, 0, nullptr, diff);
    require(err.code == graph_document::graph_error_code_t::graph_too_large,
            "graph generation diffs must enforce the global edge cap");
}

void verify_graph_layout_cancellation()
{
    graph_source_t source(100, 99);
    graph_document::graph_document_model_t model(source);

    cancellation_flag_t cancel_flag;
    cancel_flag.cancel();

    graph_document::graph_layout_request_t layout_req;
    layout_req.expected_generation = model.bound_generation();
    layout_req.max_nodes = 200;
    layout_req.canvas_width = 1024.0f;
    layout_req.canvas_height = 768.0f;

    graph_document::graph_layout_t layout;
    auto err = model.compute_layout(layout_req, &cancel_flag, layout);
    require(err.code == graph_document::graph_error_code_t::layout_cancelled,
            "graph layout with cancellation must return layout_cancelled");
    require(layout.cancelled, "graph layout must report cancelled flag");

    const std::uint64_t phase_triggers[] = {420, 750, 850, 950};
    for (const auto trigger : phase_triggers) {
        graph_phase_cancellation_t phase_cancel(trigger);
        err = model.compute_layout(layout_req, &phase_cancel, layout);
        require(err.code == graph_document::graph_error_code_t::layout_cancelled,
                "graph post-load phase cancellation must return layout_cancelled");
        require(layout.cancelled && !layout.complete,
                "graph post-load phase cancellation must preserve incomplete state");
        require(phase_cancel.checks() >= trigger,
                "graph post-load phase cancellation must reach its requested phase");
    }
}

void verify_graph_deterministic_ids()
{
    auto id1 = graph_document::compute_deterministic_node_id(0x401000U);
    auto id2 = graph_document::compute_deterministic_node_id(0x401000U);
    require(id1 == id2, "deterministic node IDs must be identical for same address");

    auto id3 = graph_document::compute_deterministic_node_id(0x401004U);
    require(id1 != id3, "deterministic node IDs must differ for different addresses");

    graph_document::graph_edge_identity_t identity;
    identity.source = id1;
    identity.target = id3;
    identity.kind = graph_document::graph_edge_kind_t::conditional_true;
    identity.site_address = 0x401002U;
    identity.parallel_ordinal = 0;
    auto e1 = graph_document::compute_deterministic_edge_id(identity);
    auto e2 = graph_document::compute_deterministic_edge_id(identity);
    require(e1 == e2, "deterministic edge IDs must be identical for the same identity");

    identity.parallel_ordinal = 1;
    auto parallel = graph_document::compute_deterministic_edge_id(identity);
    require(e1 != parallel,
            "parallel edges must have distinct deterministic identities");

    identity.source = id3;
    identity.target = id1;
    identity.parallel_ordinal = 0;
    auto e3 = graph_document::compute_deterministic_edge_id(identity);
    require(e1 != e3, "deterministic edge IDs must differ for reversed direction");

    require(!graph_document::compute_deterministic_node_id(0).valid(),
            "deterministic node ID for zero address must be invalid");

    graph_source_t source(2, 2);
    source.enable_parallel_edges();
    graph_document::graph_document_model_t model(source);
    graph_document::graph_page_request_t request;
    request.limit = 2;
    request.edges = true;
    graph_document::graph_page_t page;
    const auto error = model.page(request, nullptr, page);
    require(error.ok() && page.edges.size() == 2,
            "parallel edge paging must preserve both edges");
    require(page.edges[0].id != page.edges[1].id,
            "parallel edge paging must expose distinct stable identities");
}

void verify_graph_cross_generation_diff()
{
    graph_source_t source(10, 9);

    const auto old_gen = source.current_generation();
    source.advance_generation();
    const auto new_gen = source.current_generation();
    graph_document::graph_document_model_t current_model(source);

    graph_document::graph_diff_result_t diff;
    auto err = current_model.diff_generations(
        old_gen, new_gen, graph_document::graph_kind_t::cfg, 0, nullptr, diff);
    require(err.ok(), "graph cross-generation diff must succeed");
    require(diff.old_generation == old_gen, "graph diff old generation must match");
    require(diff.new_generation == new_gen, "graph diff new generation must match");

    std::uint64_t added = 0, removed = 0;
    for (const auto& entry : diff.entries) {
        if (entry.kind == graph_document::graph_diff_entry_t::kind_t::node_added)
            ++added;
        if (entry.kind == graph_document::graph_diff_entry_t::kind_t::node_removed)
            ++removed;
    }
    require(added == 2, "graph diff must report 2 added nodes after generation advance");
    require(removed == 0, "graph diff must report 0 removed nodes");
}

void verify_graph_missing_node()
{
    graph_source_t source(10, 9);
    graph_document::graph_document_model_t model(source);

    graph_document::graph_navigation_request_t nav;
    nav.address = 0x999999U;

    graph_document::graph_navigation_result_t result;
    auto err = model.navigate(nav, model.bound_generation(),
                              graph_document::graph_kind_t::cfg, 0, result);
    require(!err.ok(), "graph navigate to missing address must fail");
    require(err.code == graph_document::graph_error_code_t::node_not_found,
            "graph navigate to missing address must return node_not_found");
    require(!result.found, "graph navigate to missing address must not set found");
}

void verify_graph_navigation_and_selection()
{
    graph_source_t source(20, 19);
    graph_document::graph_document_model_t model(source);

    graph_document::graph_navigation_request_t nav;
    nav.address = 0x500000U + 5 * 0x10;
    nav.page_size = 4;
    nav.select_node = true;

    graph_document::graph_navigation_result_t result;
    auto err = model.navigate(nav, model.bound_generation(),
                              graph_document::graph_kind_t::cfg, 0, result);
    require(err.ok() && result.found, "graph navigate to existing node must succeed");
    require(model.selection().node == result.node,
            "graph navigation must synchronize the selected node");
    require(model.selection().address == nav.address,
            "graph navigation must synchronize the selected address");
    require(result.page_offset == 4,
            "graph navigation must use the requested page size");
    require(result.focus_requested,
            "graph navigation must preserve the focus request");

    graph_document::graph_selection_t sel;
    sel.kind = selection_kind_t::entity;
    sel.node = result.node;
    err = model.select(sel, model.bound_generation());
    require(err.ok(), "graph select must succeed");
    require(model.selection().node == result.node, "graph selection must preserve node");

    err = model.clear_selection(model.bound_generation());
    require(err.ok(), "graph clear selection must succeed for the bound generation");
    require(model.selection().kind == selection_kind_t::none,
            "graph selection must be none after clear");
}

void verify_graph_page()
{
    graph_source_t source(100, 99);
    graph_document::graph_document_model_t model(source);

    graph_document::graph_page_request_t req;
    req.offset = 0;
    req.limit = 50;
    req.edges = false;

    graph_document::graph_page_t page;
    auto err = model.page(req, nullptr, page);
    require(err.ok(), "graph page must succeed");
    require(page.nodes.size() == 50, "graph first page must return 50 nodes");
    require(page.total_items == 100, "graph page total must be 100");

    req.offset = 0;
    req.limit = 50;
    req.edges = true;
    err = model.page(req, nullptr, page);
    require(err.ok(), "graph edge page must succeed");
    require(page.edges.size() == 50, "graph first edge page must return 50 edges");
    require(page.nodes.empty(), "graph edge page must not retain stale node rows");

    graph_overlay_t overlays;
    const auto first_node = graph_document::compute_deterministic_node_id(0x500000U);
    overlays.set(first_node, "overlay_bb_0");
    graph_document::graph_document_model_t overlay_model(source, &overlays);
    req.edges = false;
    req.limit = 1;
    err = overlay_model.page(req, nullptr, page);
    require(err.ok(), "graph page with overlays must succeed");
    require(page.nodes.size() == 1 && page.nodes[0].label == "overlay_bb_0",
            "graph node labels must project active overlays");

    overlays.set_reported_count(graph_document::k_graph_document_max_overlays + 1U);
    err = overlay_model.page(req, nullptr, page);
    require(err.code == graph_document::graph_error_code_t::resource_exhausted,
            "graph overlay projection must enforce the overlay cap");
}

class diff_source_t final : public diff_document::diff_source_adapter_t {
public:
    diff_source_t(std::uint64_t entry_count)
        : entry_count_(entry_count) {}

    void advance_generation() { ++generation_; }
    void force_domain(diff_document::diff_domain_t domain) noexcept
    {
        forced_domain_ = domain;
        has_forced_domain_ = true;
    }
    void set_entity_only_index(std::uint64_t index) noexcept
    {
        entity_only_index_ = index;
    }
    void reset_entry_reads() const noexcept { entry_reads_ = 0; }
    std::uint64_t entry_reads() const noexcept { return entry_reads_; }

    std::uint64_t current_generation() const noexcept override { return generation_; }
    bool generation_current(std::uint64_t gen) const noexcept override
    {
        return gen == generation_;
    }
    bool supports_kind(diff_document::diff_kind_t kind) const noexcept override
    {
        return kind <= diff_document::diff_kind_t::workspace;
    }
    bool scope_available(
        std::uint64_t gen,
        const diff_document::diff_scope_t& scope) const noexcept override
    {
        return gen == generation_ && diff_document::diff_scope_valid(scope);
    }

    std::uint64_t entry_count(
        std::uint64_t gen,
        const diff_document::diff_scope_t& scope) const noexcept override
    {
        return gen == generation_ && diff_document::diff_scope_valid(scope)
            ? entry_count_
            : 0;
    }

    bool entry_at(std::uint64_t gen,
                  const diff_document::diff_scope_t& scope,
                   std::uint64_t ordinal,
                   diff_document::diff_entry_t& output) const noexcept override
    {
        if (gen != generation_ || !diff_document::diff_scope_valid(scope) ||
            ordinal >= entry_count_) {
            return false;
        }
        ++entry_reads_;
        output.kind = (ordinal % 4 == 0) ? diff_document::diff_entry_kind_t::added :
                     (ordinal % 4 == 1) ? diff_document::diff_entry_kind_t::removed :
                     (ordinal % 4 == 2) ? diff_document::diff_entry_kind_t::modified :
                                          diff_document::diff_entry_kind_t::moved;
        output.domain = has_forced_domain_
            ? forced_domain_
            : static_cast<diff_document::diff_domain_t>(ordinal % 9);
        const auto address = 0x401000U + ordinal * 4;
        output.address = address;
        output.entity_key = "entity_" + std::to_string(ordinal);
        const auto kind_name = scope.kind == diff_document::diff_kind_t::generation
            ? "generation"
            : scope.kind == diff_document::diff_kind_t::overlay
                ? "overlay"
                : "workspace";
        output.old_value = std::string(kind_name) + "_old_" + std::to_string(ordinal);
        output.new_value = std::string(kind_name) + "_new_" + std::to_string(ordinal);
        if (output.kind == diff_document::diff_entry_kind_t::added)
            output.new_address = address;
        else if (output.kind == diff_document::diff_entry_kind_t::removed)
            output.old_address = address;
        else if (output.kind == diff_document::diff_entry_kind_t::modified) {
            output.old_address = address;
            output.new_address = address;
        } else {
            output.old_address = address;
            output.new_address = address + 0x100000U;
            output.address = output.new_address;
        }
        if (ordinal == entity_only_index_) {
            output.kind = diff_document::diff_entry_kind_t::modified;
            output.address = 0;
            output.old_address = 0;
            output.new_address = 0;
        }
        return true;
    }

    bool summary(std::uint64_t gen,
                 const diff_document::diff_scope_t& scope,
                 diff_document::diff_summary_t& output) const noexcept override
    {
        if (gen != generation_ || !diff_document::diff_scope_valid(scope))
            return false;
        output = {};
        output.snapshot_generation = gen;
        output.scope = scope;
        output.total_entries = entry_count_;
        for (std::uint64_t i = 0; i < entry_count_; ++i) {
            const auto remainder = i % 4;
            if (remainder == 0) ++output.added_count;
            else if (remainder == 1) ++output.removed_count;
            else if (remainder == 2) ++output.modified_count;
            else ++output.moved_count;
        }
        return true;
    }

private:
    std::uint64_t generation_ = 1;
    std::uint64_t entry_count_;
    bool has_forced_domain_ = false;
    diff_document::diff_domain_t forced_domain_ =
        diff_document::diff_domain_t::instruction;
    std::uint64_t entity_only_index_ = ~0ULL;
    mutable std::uint64_t entry_reads_ = 0;
};

diff_document::diff_scope_t generation_diff_scope()
{
    diff_document::diff_scope_t scope;
    scope.kind = diff_document::diff_kind_t::generation;
    scope.before = {1, 10, 0};
    scope.after = {1, 11, 0};
    return scope;
}

diff_document::diff_scope_t overlay_diff_scope()
{
    diff_document::diff_scope_t scope;
    scope.kind = diff_document::diff_kind_t::overlay;
    scope.before = {1, 11, 2};
    scope.after = {1, 11, 3};
    return scope;
}

diff_document::diff_scope_t workspace_diff_scope()
{
    diff_document::diff_scope_t scope;
    scope.kind = diff_document::diff_kind_t::workspace;
    scope.before = {1, 11, 0};
    scope.after = {2, 7, 0};
    return scope;
}

void verify_diff_page_and_navigation()
{
    diff_source_t source(1000);
    diff_document::diff_document_model_t model(source);
    const auto scope = generation_diff_scope();

    diff_document::diff_page_request_t req;
    req.offset = 0;
    req.limit = 100;

    diff_document::diff_page_t page;
    auto err = model.page(req, model.bound_generation(), scope, nullptr, page);
    require(err.ok(), "diff page must succeed");
    require(page.entries.size() == 100, "diff first page must return 100 entries");
    require(page.total_entries == 1000, "diff page total must be 1000");

    req.offset = 990;
    req.limit = 100;
    err = model.page(req, model.bound_generation(), scope, nullptr, page);
    require(err.ok() && page.entries.size() == 10, "diff last page must return 10 entries");

    diff_document::diff_navigation_request_t nav;
    nav.entry_index = 500;
    nav.page_size = 100;
    diff_document::diff_navigation_result_t nav_result;
    err = model.navigate(nav, model.bound_generation(), scope, nav_result);
    require(err.ok() && nav_result.found, "diff navigate to valid index must succeed");
    require(nav_result.entry_index == 500, "diff navigate entry index must match");
    require(nav_result.page_offset == 500,
            "diff navigation must use the requested page size");
    require(nav_result.selection.kind == selection_kind_t::address &&
                nav_result.selection.address == 0x401000U + 500 * 4,
            "diff address navigation must resolve the entry address");
    require(model.selection().address == nav_result.selection.address,
            "diff navigation must synchronize address selection");

    source.set_entity_only_index(501);
    nav.entry_index = 501;
    err = model.navigate(nav, model.bound_generation(), scope, nav_result);
    require(err.ok() && nav_result.selection.kind == selection_kind_t::entity,
            "addressless diff navigation must resolve an entity selection");
    require(nav_result.selection.entity_key == "entity_501",
            "diff entity navigation must preserve the entity key");

    nav.entry_index = 2000;
    err = model.navigate(nav, model.bound_generation(), scope, nav_result);
    require(!err.ok(), "diff navigate to out-of-range index must fail");
}

void verify_diff_summary_and_selection()
{
    diff_source_t source(100);
    diff_document::diff_document_model_t model(source);
    const auto scope = generation_diff_scope();

    diff_document::diff_summary_t s;
    auto err = model.compute_summary(model.bound_generation(), scope, s);
    require(err.ok(), "diff summary must succeed");
    require(s.total_entries == 100, "diff summary total must be 100");
    require(s.added_count == 25, "diff summary added count must be 25");
    require(s.removed_count == 25, "diff summary removed count must be 25");
    require(s.modified_count == 25, "diff summary modified count must be 25");
    require(s.moved_count == 25, "diff summary moved count must be 25");

    diff_document::diff_navigation_request_t navigation;
    navigation.entry_index = 5;
    navigation.select_entry = false;
    diff_document::diff_navigation_result_t navigation_result;
    err = model.navigate(navigation, model.bound_generation(), scope,
                         navigation_result);
    require(err.ok(), "diff selection fixture navigation must succeed");
    err = model.select(navigation_result.selection, model.bound_generation(), scope);
    require(err.ok(), "diff select must succeed");
    require(model.selection().entry_index == 5, "diff selection must preserve entry index");

    err = model.clear_selection(model.bound_generation());
    require(err.ok(), "diff clear selection must succeed");
    require(model.selection().kind == selection_kind_t::none,
            "diff selection must be none after clear");
}

void verify_diff_stale_generation()
{
    diff_source_t source(100);
    diff_document::diff_document_model_t model(source);

    require(!model.is_stale(), "diff model must not be stale initially");
    const auto bound_generation = model.bound_generation();
    source.advance_generation();
    require(model.is_stale(), "diff model must be stale after source advance");

    diff_document::diff_command_t cmd;
    cmd.kind = diff_document::diff_command_kind_t::refresh;
    cmd.expected_generation = bound_generation;
    auto result = model.execute(cmd);
    require(result.error.code == diff_document::diff_error_code_t::stale_generation &&
                !result.changed,
            "diff refresh must reject an expired generation lease");
    require(model.is_stale(),
            "diff refresh must not rebind an expired generation lease");

    diff_document::diff_document_model_t rebound_model(source);
    require(!rebound_model.is_stale() &&
                rebound_model.bound_generation() == source.current_generation(),
            "a new diff model must bind the current immutable generation");
}

void verify_diff_domain_filter()
{
    diff_source_t source(100);
    diff_document::diff_document_model_t model(source);
    const auto scope = generation_diff_scope();

    diff_document::diff_page_request_t req;
    req.offset = 0;
    req.limit = 100;
    req.domain_filter = diff_document::diff_domain_t::instruction;

    diff_document::diff_page_t page;
    auto err = model.page(req, model.bound_generation(), scope, nullptr, page);
    require(err.ok(), "diff page with domain filter must succeed");
    for (const auto& e : page.entries)
        require(e.domain == diff_document::diff_domain_t::instruction,
                "diff page domain filter must only return matching entries");

    diff_source_t bounded_source(diff_document::k_diff_document_max_entries);
    bounded_source.force_domain(diff_document::diff_domain_t::instruction);
    diff_document::diff_document_model_t bounded_model(bounded_source);
    req.offset = 0;
    req.limit = diff_document::k_diff_document_max_page_size;
    req.domain_filter = diff_document::diff_domain_t::type;
    bounded_source.reset_entry_reads();
    err = bounded_model.page(req, bounded_model.bound_generation(), scope,
                             nullptr, page);
    require(err.ok() && page.entries.empty(),
            "diff filtered page without matches must succeed with an empty page");
    require(page.scanned_entries == diff_document::k_diff_document_max_filtered_scan,
            "diff filtered page must stop at the bounded scan ceiling");
    require(bounded_source.entry_reads() ==
                diff_document::k_diff_document_max_filtered_scan,
            "diff filtered page must not read beyond the scan ceiling");
    require(page.next_offset == diff_document::k_diff_document_max_filtered_scan,
            "diff filtered page must return a resumable raw offset");
}

void verify_diff_cancellation()
{
    diff_source_t source(100);
    diff_document::diff_document_model_t model(source);
    const auto scope = generation_diff_scope();

    cancellation_flag_t cancel_flag;
    cancel_flag.cancel();

    diff_document::diff_page_request_t req;
    req.offset = 0;
    req.limit = 100;

    diff_document::diff_page_t page;
    auto err = model.page(req, model.bound_generation(), scope, &cancel_flag, page);
    require(err.code == diff_document::diff_error_code_t::cancelled,
            "diff page with cancellation must return cancelled");
}

void verify_diff_expected_generation_and_caps()
{
    const auto scope = generation_diff_scope();
    diff_source_t source(100);
    diff_document::diff_document_model_t model(source);

    diff_document::diff_command_t command;
    command.kind = diff_document::diff_command_kind_t::page;
    command.expected_generation = model.bound_generation() + 1;
    command.scope = scope;
    command.page_request.limit = 1;
    source.reset_entry_reads();
    auto result = model.execute(command);
    require(result.error.code == diff_document::diff_error_code_t::stale_generation,
            "diff commands must reject a mismatched expected_generation");
    require(source.entry_reads() == 0,
            "diff stale-generation rejection must occur before entry traversal");

    diff_source_t oversized_source(diff_document::k_diff_document_max_entries + 1ULL);
    diff_document::diff_document_model_t oversized_model(oversized_source);
    diff_document::diff_page_t page;
    auto err = oversized_model.page(command.page_request,
                                    oversized_model.bound_generation(), scope,
                                    nullptr, page);
    require(err.code == diff_document::diff_error_code_t::resource_exhausted,
            "diff paging must enforce the entry cap");

    diff_document::diff_navigation_request_t navigation;
    diff_document::diff_navigation_result_t navigation_result;
    err = oversized_model.navigate(navigation, oversized_model.bound_generation(),
                                   scope, navigation_result);
    require(err.code == diff_document::diff_error_code_t::resource_exhausted,
            "diff navigation must enforce the entry cap");

    diff_document::diff_summary_t summary;
    err = oversized_model.compute_summary(oversized_model.bound_generation(),
                                          scope, summary);
    require(err.code == diff_document::diff_error_code_t::resource_exhausted,
            "diff summaries must enforce the entry cap");
}

void verify_diff_scope_semantics()
{
    const auto generation_scope = generation_diff_scope();
    const auto overlay_scope = overlay_diff_scope();
    const auto workspace_scope = workspace_diff_scope();
    require(diff_document::diff_scope_valid(generation_scope),
            "generation diff scope must be valid");
    require(diff_document::diff_scope_valid(overlay_scope),
            "overlay diff scope must be valid");
    require(diff_document::diff_scope_valid(workspace_scope),
            "workspace diff scope must be valid");

    auto invalid_scope = generation_scope;
    invalid_scope.after.workspace_id = 2;
    require(!diff_document::diff_scope_valid(invalid_scope),
            "generation diff must reject cross-workspace endpoints");
    invalid_scope = overlay_scope;
    invalid_scope.after.generation = 12;
    require(!diff_document::diff_scope_valid(invalid_scope),
            "overlay diff must reject cross-generation endpoints");
    invalid_scope = workspace_scope;
    invalid_scope.after.workspace_id = invalid_scope.before.workspace_id;
    require(!diff_document::diff_scope_valid(invalid_scope),
            "workspace diff must require distinct workspaces");

    diff_source_t source(4);
    diff_document::diff_document_model_t model(source);
    diff_document::diff_page_request_t request;
    request.limit = 1;
    const auto verify_scope = [&](const diff_document::diff_scope_t& scope,
                                  const std::string& prefix) {
        diff_document::diff_page_t page;
        const auto error = model.page(request, model.bound_generation(), scope,
                                      nullptr, page);
        require(error.ok() && page.scope == scope && page.entries.size() == 1,
                "concrete diff scope page must preserve endpoint identity");
        require(page.entries[0].old_value.rfind(prefix, 0) == 0,
                "concrete diff scope must route to kind-specific source semantics");
    };
    verify_scope(generation_scope, "generation_old_");
    verify_scope(overlay_scope, "overlay_old_");
    verify_scope(workspace_scope, "workspace_old_");
}

}

bool run_workbench_documents_harness(std::string& failure)
{
    try {
        verify_disasm_large_virtual_model();
        verify_disasm_stale_generation();
        verify_disasm_overlay_visualization();
        verify_disasm_cross_document_navigation();
        verify_disasm_command_routing();
        verify_disasm_limits_and_selection();
        verify_navigation_event_bridge();
        verify_production_document_bridge();

        verify_hex_large_virtual_model();
        verify_hex_stale_and_overlay();
        verify_hex_patch_projection_limits_and_selection();
        verify_hex_cross_document_navigation();

        verify_independent_workspace_fixtures();

        verify_pseudocode_explicit_request_only();
        verify_pseudocode_request_and_cache();
        verify_pseudocode_tokens_diagnostics_and_mapping();
        verify_pseudocode_cancellation();
        verify_pseudocode_stale_result();
        verify_pseudocode_worker_failure();
        verify_pseudocode_multi_workspace();

        verify_graph_large_cap();
        verify_graph_layout_cancellation();
        verify_graph_deterministic_ids();
        verify_graph_cross_generation_diff();
        verify_graph_missing_node();
        verify_graph_navigation_and_selection();
        verify_graph_page();

        verify_diff_page_and_navigation();
        verify_diff_summary_and_selection();
        verify_diff_stale_generation();
        verify_diff_domain_filter();
        verify_diff_cancellation();
        verify_diff_expected_generation_and_caps();
        verify_diff_scope_semantics();

        failure.clear();
        return true;
    } catch (const std::exception& exception) {
        failure = exception.what();
        return false;
    }
}

}
}

int main()
{
    std::string failure;
    if (!aida::workbench::run_workbench_documents_harness(failure)) {
        std::cerr << "workbench_documents_harness failed: " << failure << '\n';
        return 1;
    }
    std::cout << "workbench_documents_harness source contract satisfied\n";
    return 0;
}
