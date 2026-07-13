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
#include <stdexcept>
#include <string>
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
        rebuild();
    }

    void advance_generation() { ++generation_; rebuild(); }

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
                disasm_document::disasm_instruction_view_t& output) const noexcept override
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
                        std::uint64_t& ordinal) const noexcept override
    {
        if (gen != generation_)
            return false;
        if (address < 0x401000U)
            return false;
        const auto offset = address - 0x401000U;
        if (offset % 4 != 0)
            return false;
        ordinal = offset / 4;
        if (ordinal >= row_count_)
            return false;
        return row_at(gen, ordinal, output);
    }

    std::uint64_t overlay_revision(std::uint64_t gen) const noexcept override
    {
        return gen;
    }

private:
    void rebuild()
    {
        mnemonics_.clear();
        operands_.clear();
        hexes_.clear();
        mnemonics_.resize(row_count_, "nop");
        operands_.resize(row_count_, "");
        hexes_.resize(row_count_, "90 90 90 90");
    }

    std::uint64_t generation_ = 1;
    std::uint64_t row_count_;
    std::vector<std::string> mnemonics_;
    std::vector<std::string> operands_;
    std::vector<std::string> hexes_;
};

class disasm_overlay_t final : public disasm_document::disasm_overlay_adapter_t {
public:
    std::uint32_t overlay_count(std::uint64_t gen) const noexcept override
    {
        return static_cast<std::uint32_t>(entries_.size());
    }

    bool overlay_at(std::uint64_t gen, std::uint32_t ordinal,
                    disasm_document::disasm_overlay_entry_t& output) const noexcept override
    {
        if (ordinal >= entries_.size())
            return false;
        output = entries_[ordinal];
        return true;
    }

    bool overlay_by_address(std::uint64_t gen, std::uint64_t address,
                            disasm_document::disasm_overlay_entry_t& output) const noexcept override
    {
        for (const auto& e : entries_) {
            if (e.address == address && e.active) {
                output = e;
                return true;
            }
        }
        return false;
    }

    workbench_error_t apply_overlay(std::uint64_t gen,
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

    workbench_error_t remove_overlay(std::uint64_t gen,
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
    explicit hex_source_t(std::uint64_t row_count)
        : row_count_(row_count)
    {
        rebuild();
    }

    void advance_generation() { ++generation_; rebuild(); }

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
                hex_document::hex_row_view_t& output) const noexcept override
    {
        if (gen != generation_ || ordinal >= row_count_)
            return false;
        output.id = hex_document::hex_row_id_t{ordinal + 1};
        output.address = ordinal * hex_document::k_hex_document_bytes_per_row;
        output.hex_text = "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90";
        output.ascii_text = "................";
        output.byte_count = hex_document::k_hex_document_bytes_per_row;
        return true;
    }

    bool row_by_address(std::uint64_t gen, std::uint64_t address,
                        hex_document::hex_row_view_t& output,
                        std::uint64_t& ordinal) const noexcept override
    {
        if (gen != generation_)
            return false;
        ordinal = address / hex_document::k_hex_document_bytes_per_row;
        if (ordinal >= row_count_)
            return false;
        return row_at(gen, ordinal, output);
    }

    std::uint64_t overlay_revision(std::uint64_t gen) const noexcept override
    {
        return gen;
    }

private:
    void rebuild()
    {
        hex_lines_.clear();
        ascii_lines_.clear();
        hex_lines_.resize(row_count_, "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90");
        ascii_lines_.resize(row_count_, "................");
    }

    std::uint64_t generation_ = 1;
    std::uint64_t row_count_;
    std::vector<std::string> hex_lines_;
    std::vector<std::string> ascii_lines_;
};

class hex_overlay_t final : public hex_document::hex_overlay_adapter_t {
public:
    std::uint32_t overlay_count(std::uint64_t gen) const noexcept override
    {
        return static_cast<std::uint32_t>(entries_.size());
    }

    bool overlay_at(std::uint64_t gen, std::uint32_t ordinal,
                    hex_document::hex_overlay_entry_t& output) const noexcept override
    {
        if (ordinal >= entries_.size())
            return false;
        output = entries_[ordinal];
        return true;
    }

    bool overlay_by_address(std::uint64_t gen, std::uint64_t address,
                            hex_document::hex_overlay_entry_t& output) const noexcept override
    {
        for (const auto& e : entries_) {
            if (e.address == address && e.active) {
                output = e;
                return true;
            }
        }
        return false;
    }

    workbench_error_t apply_overlay(std::uint64_t gen,
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

    workbench_error_t remove_overlay(std::uint64_t gen,
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
    disasm_document::disasm_document_model_t model(source);
    const auto original_gen = model.bound_generation();

    source.advance_generation();

    require(model.is_stale(), "disasm model must detect stale generation");
    require(!model.generation_current(original_gen), "disasm model must report old generation as not current");

    disasm_document::disasm_command_t cmd;
    cmd.kind = disasm_document::disasm_command_kind_t::refresh;
    auto result = model.execute(cmd);
    require(result.changed, "disasm refresh must update bound generation");
    require(!model.is_stale(), "disasm model must not be stale after refresh");

    disasm_document::disasm_page_request_t req;
    req.offset = 0;
    req.limit = 10;
    disasm_document::disasm_page_t page;
    auto err = model.page(req, nullptr, page);
    require(err.ok() && page.rows.size() == 10, "disasm page must work after refresh");
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
        if (row.overlay != nullptr) {
            found_overlay = true;
            require(row.overlay->text == "loop_start", "disasm overlay text must match");
        }
    }
    require(found_overlay, "disasm overlay must be visible on matching row");

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
    result = model.execute(clear_cmd);
    require(result.changed, "disasm clear selection must report changed");
    require(model.selection().kind == selection_kind_t::none,
            "disasm selection must be none after clear");

    disasm_document::disasm_command_t page_cmd;
    page_cmd.kind = disasm_document::disasm_command_kind_t::page;
    page_cmd.page_request.offset = 0;
    page_cmd.page_request.limit = 50;
    result = model.execute(page_cmd);
    require(result.error.ok() && result.page.rows.size() == 50,
            "disasm page command must return rows");
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

    hex_document::hex_command_t cmd;
    cmd.kind = hex_document::hex_command_kind_t::refresh;
    auto result = model.execute(cmd);
    require(result.changed, "hex refresh must update generation");
    require(!model.is_stale(), "hex model must not be stale after refresh");
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
        pending_jobs_.push_back(job_id);
        return {};
    }

    workbench_error_t cancel_decompilation(std::uint64_t job_id) override
    {
        auto it = std::find(pending_jobs_.begin(), pending_jobs_.end(), job_id);
        if (it != pending_jobs_.end())
            pending_jobs_.erase(it);
        cancelled_jobs_.push_back(job_id);
        return {};
    }

    bool poll_result(std::uint64_t job_id,
                     aida::analysis::decompiler_document_t& output) override
    {
        auto it = std::find(pending_jobs_.begin(), pending_jobs_.end(), job_id);
        if (it == pending_jobs_.end())
            return false;
        pending_jobs_.erase(it);
        output.schema_version = aida::analysis::k_decompiler_document_schema_version;
        output.rendered_text = "int main() {\n  return 0;\n}\n";
        output.tokens.clear();
        aida::analysis::decompiler_document_token_t tok;
        tok.kind = aida::analysis::decompiler_document_token_kind_t::keyword;
        tok.range.begin = 0;
        tok.range.end = 3;
        output.tokens.push_back(tok);
        completed_jobs_.push_back(job_id);
        return true;
    }

    bool poll_failure(std::uint64_t job_id,
                      std::vector<aida::analysis::decompiler_diagnostic_t>& output) override
    {
        return false;
    }

    bool job_active(std::uint64_t job_id) const noexcept override
    {
        return std::find(pending_jobs_.begin(), pending_jobs_.end(), job_id) !=
               pending_jobs_.end();
    }

    aida::analysis::decompiler_profile_budget_t profile_budget(
        aida::analysis::decompiler_profile_id_t profile) const noexcept override
    {
        aida::analysis::decompiler_profile_budget_t budget;
        budget.profile = profile;
        budget.max_wall_clock_ms = 30000;
        budget.max_cpu_ms = 30000;
        budget.max_memory_bytes = 1ULL << 30;
        return budget;
    }

    void force_complete(std::uint64_t job_id)
    {
        auto it = std::find(pending_jobs_.begin(), pending_jobs_.end(), job_id);
        if (it != pending_jobs_.end())
            pending_jobs_.erase(it);
        completed_jobs_.push_back(job_id);
    }

private:
    std::uint64_t generation_ = 1;
    bool fail_next_ = false;
    std::vector<std::uint64_t> pending_jobs_;
    std::vector<std::uint64_t> completed_jobs_;
    std::vector<std::uint64_t> cancelled_jobs_;
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
    req.entity.kind = aida::analysis::decompiler_entity_kind_t::native_function;
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

    source.force_complete(job_id);

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
}

void verify_pseudocode_cancellation()
{
    pseudo_source_t source;
    pseudocode_document::pseudocode_document_model_t model(source);

    pseudocode_document::pseudocode_request_t req;
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
    req.workspace_generation = model.current_generation();
    auto err = model.request(req);
    require(err.ok(), "pseudocode request for stale test must succeed");
    const auto job_id = model.cached_document()->job_id;

    source.force_complete(job_id);

    err = model.poll(job_id);
    require(err.ok(), "pseudocode poll must succeed");
    require(model.cache_state() == pseudocode_document::pseudocode_cache_state_t::cached,
            "pseudocode must be cached before stale check");

    source.advance_generation();
    model.refresh();
    require(model.is_stale(), "pseudocode must be stale after generation advance and refresh");
}

void verify_pseudocode_worker_failure()
{
    pseudo_source_t source;
    source.set_fail_next(true);
    pseudocode_document::pseudocode_document_model_t model(source);

    pseudocode_document::pseudocode_request_t req;
    req.workspace_generation = model.current_generation();
    auto err = model.request(req);
    require(!err.ok(), "pseudocode request with failing source must fail");
    require(err.code == pseudocode_document::pseudocode_error_code_t::adapter_rejected,
            "pseudocode request failure must return adapter_rejected");
}

void verify_pseudocode_multi_workspace()
{
    pseudo_source_t source_a;
    pseudo_source_t source_b;
    pseudocode_document::pseudocode_document_model_t model_a(source_a);
    pseudocode_document::pseudocode_document_model_t model_b(source_b);

    pseudocode_document::pseudocode_request_t req;
    req.workspace_generation = model_a.current_generation();
    auto err = model_a.request(req);
    require(err.ok(), "workspace A pseudocode request must succeed");

    req.workspace_generation = model_b.current_generation();
    err = model_b.request(req);
    require(err.ok(), "workspace B pseudocode request must succeed");

    source_a.advance_generation();
    require(model_a.is_stale(), "workspace A pseudocode must be stale");
    require(!model_b.is_stale(), "workspace B pseudocode must not be stale");
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

    std::uint64_t current_generation() const noexcept override { return generation_; }
    bool generation_current(std::uint64_t gen) const noexcept override
    {
        return gen == generation_;
    }
    graph_document::graph_kind_t supported_kind() const noexcept override
    {
        return graph_document::graph_kind_t::cfg;
    }

    std::uint64_t node_count(std::uint64_t gen, graph_document::graph_kind_t kind,
                             std::uint64_t func_addr) const noexcept override
    {
        if (gen == 0 || gen > generation_)
            return 0;
        return generations_[gen - 1].node_count;
    }

    std::uint64_t edge_count(std::uint64_t gen, graph_document::graph_kind_t kind,
                             std::uint64_t func_addr) const noexcept override
    {
        if (gen == 0 || gen > generation_)
            return 0;
        return generations_[gen - 1].edge_count;
    }

    bool node_at(std::uint64_t gen, graph_document::graph_kind_t kind,
                 std::uint64_t func_addr, std::uint64_t ordinal,
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

    bool edge_at(std::uint64_t gen, graph_document::graph_kind_t kind,
                 std::uint64_t func_addr, std::uint64_t ordinal,
                 graph_document::graph_edge_view_t& output) const noexcept override
    {
        if (gen == 0 || gen > generation_)
            return false;
        const auto ec = generations_[gen - 1].edge_count;
        if (ordinal >= ec)
            return false;
        const auto src = graph_document::compute_deterministic_node_id(0x500000U + ordinal * 0x10);
        const auto tgt = graph_document::compute_deterministic_node_id(0x500000U + (ordinal + 1) * 0x10);
        output.id = graph_document::compute_deterministic_edge_id(src, tgt);
        output.source = src;
        output.target = tgt;
        output.kind = graph_document::graph_edge_kind_t::unconditional;
        output.site_address = 0x500000U + ordinal * 0x10 + 4;
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

    graph_document::graph_node_id_t deterministic_node_id(
        std::uint64_t address) const noexcept override
    {
        return graph_document::compute_deterministic_node_id(address);
    }

    graph_document::graph_edge_id_t deterministic_edge_id(
        graph_document::graph_node_id_t source,
        graph_document::graph_node_id_t target) const noexcept override
    {
        return graph_document::compute_deterministic_edge_id(source, target);
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
    std::vector<generation_data_t> generations_;
    std::vector<std::string> labels_;
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
}

void verify_graph_deterministic_ids()
{
    auto id1 = graph_document::compute_deterministic_node_id(0x401000U);
    auto id2 = graph_document::compute_deterministic_node_id(0x401000U);
    require(id1 == id2, "deterministic node IDs must be identical for same address");

    auto id3 = graph_document::compute_deterministic_node_id(0x401004U);
    require(id1 != id3, "deterministic node IDs must differ for different addresses");

    auto e1 = graph_document::compute_deterministic_edge_id(id1, id3);
    auto e2 = graph_document::compute_deterministic_edge_id(id1, id3);
    require(e1 == e2, "deterministic edge IDs must be identical for same source/target");

    auto e3 = graph_document::compute_deterministic_edge_id(id3, id1);
    require(e1 != e3, "deterministic edge IDs must differ for reversed direction");

    require(!graph_document::compute_deterministic_node_id(0).valid(),
            "deterministic node ID for zero address must be invalid");
}

void verify_graph_cross_generation_diff()
{
    graph_source_t source(10, 9);
    graph_document::graph_document_model_t model(source);

    const auto old_gen = source.current_generation();
    source.advance_generation();
    const auto new_gen = source.current_generation();

    graph_document::graph_diff_result_t diff;
    auto err = model.diff_generations(old_gen, new_gen, graph_document::graph_kind_t::cfg, 0, diff);
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
    nav.select_node = true;

    graph_document::graph_navigation_result_t result;
    auto err = model.navigate(nav, model.bound_generation(),
                              graph_document::graph_kind_t::cfg, 0, result);
    require(err.ok() && result.found, "graph navigate to existing node must succeed");

    graph_document::graph_selection_t sel;
    sel.kind = selection_kind_t::entity;
    sel.node = result.node;
    err = model.select(sel);
    require(err.ok(), "graph select must succeed");
    require(model.selection().node == result.node, "graph selection must preserve node");

    model.clear_selection();
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
}

class diff_source_t final : public diff_document::diff_source_adapter_t {
public:
    diff_source_t(std::uint64_t entry_count)
        : entry_count_(entry_count)
    {
        rebuild();
    }

    void advance_generation() { ++generation_; rebuild(); }

    std::uint64_t current_generation() const noexcept override { return generation_; }
    bool generation_current(std::uint64_t gen) const noexcept override
    {
        return gen == generation_;
    }
    diff_document::diff_kind_t supported_kind() const noexcept override
    {
        return diff_document::diff_kind_t::generation;
    }

    std::uint64_t entry_count(std::uint64_t gen, diff_document::diff_kind_t kind,
                              std::uint64_t old_gen, std::uint64_t new_gen) const noexcept override
    {
        return gen == generation_ ? entry_count_ : 0;
    }

    bool entry_at(std::uint64_t gen, diff_document::diff_kind_t kind,
                  std::uint64_t old_gen, std::uint64_t new_gen,
                  std::uint64_t ordinal,
                  diff_document::diff_entry_t& output) const noexcept override
    {
        if (gen != generation_ || ordinal >= entry_count_)
            return false;
        output.kind = (ordinal % 4 == 0) ? diff_document::diff_entry_kind_t::added :
                     (ordinal % 4 == 1) ? diff_document::diff_entry_kind_t::removed :
                     (ordinal % 4 == 2) ? diff_document::diff_entry_kind_t::modified :
                                          diff_document::diff_entry_kind_t::moved;
        output.domain = static_cast<diff_document::diff_domain_t>(ordinal % 9);
        output.address = 0x401000U + ordinal * 4;
        output.entity_key = "entity_" + std::to_string(ordinal);
        output.old_value = "old_" + std::to_string(ordinal);
        output.new_value = "new_" + std::to_string(ordinal);
        return true;
    }

    diff_document::diff_summary_t summary(std::uint64_t gen, diff_document::diff_kind_t kind,
                                          std::uint64_t old_gen,
                                          std::uint64_t new_gen) const noexcept override
    {
        diff_document::diff_summary_t s;
        s.kind = kind;
        s.old_generation = old_gen;
        s.new_generation = new_gen;
        s.total_entries = entry_count_;
        for (std::uint64_t i = 0; i < entry_count_; ++i) {
            auto m = i % 4;
            if (m == 0) ++s.added_count;
            else if (m == 1) ++s.removed_count;
            else if (m == 2) ++s.modified_count;
            else ++s.moved_count;
        }
        return s;
    }

private:
    void rebuild() {}

    std::uint64_t generation_ = 1;
    std::uint64_t entry_count_;
};

void verify_diff_page_and_navigation()
{
    diff_source_t source(1000);
    diff_document::diff_document_model_t model(source);

    diff_document::diff_page_request_t req;
    req.offset = 0;
    req.limit = 100;

    diff_document::diff_page_t page;
    auto err = model.page(req, diff_document::diff_kind_t::generation, 1, 2, nullptr, page);
    require(err.ok(), "diff page must succeed");
    require(page.entries.size() == 100, "diff first page must return 100 entries");
    require(page.total_entries == 1000, "diff page total must be 1000");

    req.offset = 990;
    req.limit = 100;
    err = model.page(req, diff_document::diff_kind_t::generation, 1, 2, nullptr, page);
    require(err.ok() && page.entries.size() == 10, "diff last page must return 10 entries");

    diff_document::diff_navigation_request_t nav;
    nav.entry_index = 500;
    diff_document::diff_navigation_result_t nav_result;
    err = model.navigate(nav, diff_document::diff_kind_t::generation, 1, 2, nav_result);
    require(err.ok() && nav_result.found, "diff navigate to valid index must succeed");
    require(nav_result.entry_index == 500, "diff navigate entry index must match");

    nav.entry_index = 2000;
    err = model.navigate(nav, diff_document::diff_kind_t::generation, 1, 2, nav_result);
    require(!err.ok(), "diff navigate to out-of-range index must fail");
}

void verify_diff_summary_and_selection()
{
    diff_source_t source(100);
    diff_document::diff_document_model_t model(source);

    auto s = model.compute_summary(diff_document::diff_kind_t::generation, 1, 2);
    require(s.total_entries == 100, "diff summary total must be 100");
    require(s.added_count == 25, "diff summary added count must be 25");
    require(s.removed_count == 25, "diff summary removed count must be 25");
    require(s.modified_count == 25, "diff summary modified count must be 25");
    require(s.moved_count == 25, "diff summary moved count must be 25");

    diff_document::diff_selection_t sel;
    sel.kind = selection_kind_t::address;
    sel.has_address = true;
    sel.address = 0x401000U;
    sel.entry_index = 5;
    auto err = model.select(sel);
    require(err.ok(), "diff select must succeed");
    require(model.selection().entry_index == 5, "diff selection must preserve entry index");

    model.clear_selection();
    require(model.selection().kind == selection_kind_t::none,
            "diff selection must be none after clear");
}

void verify_diff_stale_generation()
{
    diff_source_t source(100);
    diff_document::diff_document_model_t model(source);

    require(!model.is_stale(), "diff model must not be stale initially");
    source.advance_generation();
    require(model.is_stale(), "diff model must be stale after source advance");

    diff_document::diff_command_t cmd;
    cmd.kind = diff_document::diff_command_kind_t::refresh;
    auto result = model.execute(cmd);
    require(result.changed, "diff refresh must update generation");
    require(!model.is_stale(), "diff model must not be stale after refresh");
}

void verify_diff_domain_filter()
{
    diff_source_t source(100);
    diff_document::diff_document_model_t model(source);

    diff_document::diff_page_request_t req;
    req.offset = 0;
    req.limit = 100;
    req.domain_filter = diff_document::diff_domain_t::instruction;

    diff_document::diff_page_t page;
    auto err = model.page(req, diff_document::diff_kind_t::generation, 1, 2, nullptr, page);
    require(err.ok(), "diff page with domain filter must succeed");
    for (const auto& e : page.entries)
        require(e.domain == diff_document::diff_domain_t::instruction,
                "diff page domain filter must only return matching entries");
}

void verify_diff_cancellation()
{
    diff_source_t source(100);
    diff_document::diff_document_model_t model(source);

    cancellation_flag_t cancel_flag;
    cancel_flag.cancel();

    diff_document::diff_page_request_t req;
    req.offset = 0;
    req.limit = 100;

    diff_document::diff_page_t page;
    auto err = model.page(req, diff_document::diff_kind_t::generation, 1, 2, &cancel_flag, page);
    require(err.code == diff_document::diff_error_code_t::cancelled,
            "diff page with cancellation must return cancelled");
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

        verify_hex_large_virtual_model();
        verify_hex_stale_and_overlay();
        verify_hex_cross_document_navigation();

        verify_independent_workspace_fixtures();

        verify_pseudocode_explicit_request_only();
        verify_pseudocode_request_and_cache();
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
