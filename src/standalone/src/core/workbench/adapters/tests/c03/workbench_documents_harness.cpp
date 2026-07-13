#include "workbench_documents_harness.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>

namespace aida::workbench::adapters::test {

mock_disasm_store_t::mock_disasm_store_t(std::uint64_t generation, std::uint64_t instruction_count)
    : generation_(generation)
    , instruction_count_(instruction_count)
    , mnemonic_storage("nop")
    , operands_storage("")
{
}

void mock_disasm_store_t::advance_generation() noexcept
{
    ++generation_;
}

std::uint64_t mock_disasm_store_t::current_generation() const noexcept
{
    return generation_;
}

bool mock_disasm_store_t::generation_current(std::uint64_t generation) const noexcept
{
    return generation == generation_;
}

std::uint64_t mock_disasm_store_t::instruction_count(std::uint64_t generation) const noexcept
{
    if (generation != generation_)
        return 0;
    return instruction_count_;
}

bool mock_disasm_store_t::instruction_at(std::uint64_t generation, std::uint64_t ordinal,
                                         disasm::disasm_instruction_view_t& output) const
{
    if (generation != generation_ || ordinal >= instruction_count_)
        return false;

    output.ordinal = ordinal;
    output.address = 0x1000 + ordinal * 4;
    output.length = 4;
    output.bytes[0] = static_cast<std::uint8_t>(ordinal & 0xFF);
    output.bytes[1] = static_cast<std::uint8_t>((ordinal >> 8) & 0xFF);
    output.bytes[2] = 0;
    output.bytes[3] = 0;
    output.mnemonic = std::string_view(mnemonic_storage);
    output.operands = std::string_view(operands_storage);
    output.comment = {};
    output.flow = disasm::disasm_flow_flag_t::fallthrough;
    output.has_target = false;
    output.function_id = 1;
    output.overlay_count = 0;
    return true;
}

bool mock_disasm_store_t::instruction_by_address(std::uint64_t generation, std::uint64_t address,
                                                  disasm::disasm_instruction_view_t& output) const
{
    if (generation != generation_)
        return false;
    if (address < 0x1000)
        return false;
    const std::uint64_t ordinal = (address - 0x1000) / 4;
    if (ordinal >= instruction_count_)
        return false;
    return instruction_at(generation, ordinal, output);
}

std::uint64_t mock_disasm_store_t::ordinal_for_address(std::uint64_t generation,
                                                       std::uint64_t address) const noexcept
{
    if (generation != generation_ || address < 0x1000)
        return 0xFFFFFFFFFFFFFFFFULL;
    return (address - 0x1000) / 4;
}

void mock_disasm_overlay_t::add_overlay(std::uint64_t address, std::uint64_t address_end,
                                        document_overlay_kind_t kind, const std::string& name)
{
    disasm::disasm_overlay_entry_t entry;
    entry.address = address;
    entry.address_end = address_end;
    entry.descriptor.revision = entries_.size() + 1;
    entry.descriptor.kind = kind;
    entry.descriptor.name = name;
    entry.descriptor.active = true;
    entry.descriptor.has_address_range = true;
    entry.descriptor.address_begin = address;
    entry.descriptor.address_end = address_end;
    entries_.push_back(std::move(entry));
}

std::uint64_t mock_disasm_overlay_t::overlay_revision(std::uint64_t) const noexcept
{
    return entries_.size();
}

std::size_t mock_disasm_overlay_t::overlay_count(std::uint64_t) const noexcept
{
    return entries_.size();
}

bool mock_disasm_overlay_t::overlay_at(std::uint64_t, std::size_t ordinal,
                                       disasm::disasm_overlay_entry_t& output) const
{
    if (ordinal >= entries_.size())
        return false;
    output = entries_[ordinal];
    return true;
}

bool mock_disasm_overlay_t::overlays_in_range(std::uint64_t, std::uint64_t address_begin,
                                              std::uint64_t address_end,
                                              std::vector<disasm::disasm_overlay_entry_t>& output) const
{
    output.clear();
    for (const auto& entry : entries_) {
        if (entry.address < address_end && entry.address_end > address_begin)
            output.push_back(entry);
    }
    return true;
}

mock_hex_store_t::mock_hex_store_t(std::uint64_t generation, std::uint64_t byte_count)
    : generation_(generation)
    , byte_count_(byte_count)
{
}

void mock_hex_store_t::advance_generation() noexcept
{
    ++generation_;
}

std::uint64_t mock_hex_store_t::current_generation() const noexcept
{
    return generation_;
}

bool mock_hex_store_t::generation_current(std::uint64_t generation) const noexcept
{
    return generation == generation_;
}

std::uint64_t mock_hex_store_t::byte_count(std::uint64_t generation) const noexcept
{
    if (generation != generation_)
        return 0;
    return byte_count_;
}

bool mock_hex_store_t::bytes_at(std::uint64_t generation, std::uint64_t offset,
                                std::uint8_t* buffer, std::uint8_t max_count,
                                std::uint8_t& actual_count) const
{
    if (generation != generation_)
        return false;
    if (offset >= byte_count_) {
        actual_count = 0;
        return true;
    }
    const std::uint64_t remaining = byte_count_ - offset;
    actual_count = static_cast<std::uint8_t>(std::min(static_cast<std::uint64_t>(max_count), remaining));
    for (std::uint8_t i = 0; i < actual_count; ++i)
        buffer[i] = static_cast<std::uint8_t>((offset + i) & 0xFF);
    return true;
}

std::uint64_t mock_hex_store_t::base_address_for_offset(std::uint64_t generation,
                                                        std::uint64_t offset) const noexcept
{
    if (generation != generation_)
        return 0;
    return 0x1000 + offset;
}

std::uint64_t mock_hex_store_t::offset_for_address(std::uint64_t generation,
                                                   std::uint64_t address) const noexcept
{
    if (generation != generation_ || address < 0x1000)
        return 0xFFFFFFFFFFFFFFFFULL;
    return address - 0x1000;
}

mock_pseudocode_store_t::mock_pseudocode_store_t(std::uint64_t generation)
    : generation_(generation)
    , ready_entity_id_(0)
    , ready_line_count_(0)
    , text_storage_("void func() {\n  return;\n}\n")
{
}

void mock_pseudocode_store_t::set_document_ready(std::uint64_t entity_id, std::uint64_t line_count)
{
    ready_entity_id_ = entity_id;
    ready_line_count_ = line_count;
}

void mock_pseudocode_store_t::advance_generation() noexcept
{
    ++generation_;
}

std::uint64_t mock_pseudocode_store_t::current_generation() const noexcept
{
    return generation_;
}

bool mock_pseudocode_store_t::generation_current(std::uint64_t generation) const noexcept
{
    return generation == generation_;
}

pseudocode::pseudocode_status_t mock_pseudocode_store_t::document_status(
    std::uint64_t generation, std::uint64_t entity_id) const noexcept
{
    if (generation != generation_)
        return pseudocode::pseudocode_status_t::stale;
    if (entity_id != ready_entity_id_ || ready_line_count_ == 0)
        return pseudocode::pseudocode_status_t::empty;
    return pseudocode::pseudocode_status_t::ready;
}

std::uint64_t mock_pseudocode_store_t::line_count(std::uint64_t generation,
                                                  std::uint64_t entity_id) const noexcept
{
    if (generation != generation_ || entity_id != ready_entity_id_)
        return 0;
    return ready_line_count_;
}

std::uint64_t mock_pseudocode_store_t::token_count(std::uint64_t generation,
                                                   std::uint64_t entity_id) const noexcept
{
    if (generation != generation_ || entity_id != ready_entity_id_)
        return 0;
    return 16;
}

std::uint64_t mock_pseudocode_store_t::source_map_count(std::uint64_t generation,
                                                        std::uint64_t entity_id) const noexcept
{
    if (generation != generation_ || entity_id != ready_entity_id_)
        return 0;
    return 1;
}

std::uint64_t mock_pseudocode_store_t::diagnostic_count(std::uint64_t generation,
                                                        std::uint64_t entity_id) const noexcept
{
    if (generation != generation_ || entity_id != ready_entity_id_)
        return 0;
    return 0;
}

bool mock_pseudocode_store_t::line_at(std::uint64_t generation, std::uint64_t entity_id,
                                      std::uint64_t ordinal,
                                      pseudocode::pseudocode_line_view_t& output) const
{
    if (generation != generation_ || entity_id != ready_entity_id_)
        return false;
    if (ordinal >= ready_line_count_)
        return false;

    output.line_number = static_cast<std::uint32_t>(ordinal + 1);
    output.begin_offset = static_cast<std::uint32_t>(ordinal * 20);
    output.end_offset = static_cast<std::uint32_t>((ordinal + 1) * 20);
    output.text = std::string_view(text_storage_);
    return true;
}

bool mock_pseudocode_store_t::token_at(std::uint64_t generation, std::uint64_t entity_id,
                                       std::uint64_t ordinal,
                                       pseudocode::pseudocode_token_view_t& output) const
{
    if (generation != generation_ || entity_id != ready_entity_id_)
        return false;
    if (ordinal >= 16)
        return false;
    output.ordinal = ordinal;
    output.token_index = static_cast<std::uint32_t>(ordinal);
    output.begin_offset = static_cast<std::uint32_t>(ordinal * 4);
    output.end_offset = static_cast<std::uint32_t>((ordinal + 1) * 4);
    output.kind = 2;
    output.ast_node_id = ordinal;
    output.text = std::string_view(text_storage_);
    return true;
}

bool mock_pseudocode_store_t::source_map_at(std::uint64_t generation, std::uint64_t entity_id,
                                            std::uint64_t ordinal,
                                            pseudocode::pseudocode_source_map_view_t& output) const
{
    if (generation != generation_ || entity_id != ready_entity_id_ || ordinal != 0)
        return false;
    output.ordinal = 0;
    output.token_begin = 0;
    output.token_end = 16;
    output.has_address_range = true;
    output.address_begin = 0x1000;
    output.address_end = 0x1010;
    output.has_instruction_range = true;
    output.first_instruction_id = 0;
    output.last_instruction_id = 4;
    output.source_path = "test.c";
    output.source_first_line = 1;
    output.source_last_line = 3;
    return true;
}

bool mock_pseudocode_store_t::diagnostic_at(std::uint64_t, std::uint64_t, std::uint64_t,
                                            pseudocode::pseudocode_diagnostic_view_t&) const
{
    return false;
}

bool mock_pseudocode_store_t::source_map_for_address(std::uint64_t generation,
                                                     std::uint64_t entity_id,
                                                     std::uint64_t address,
                                                     pseudocode::pseudocode_source_map_view_t& output) const
{
    if (generation != generation_ || entity_id != ready_entity_id_)
        return false;
    if (address < 0x1000 || address >= 0x1010)
        return false;
    return source_map_at(generation, entity_id, 0, output);
}

bool mock_pseudocode_store_t::source_map_for_token_range(std::uint64_t generation,
                                                         std::uint64_t entity_id,
                                                         std::uint32_t token_begin,
                                                         std::uint32_t token_end,
                                                         pseudocode::pseudocode_source_map_view_t& output) const
{
    if (generation != generation_ || entity_id != ready_entity_id_)
        return false;
    if (token_begin > 16 || token_end > 16)
        return false;
    return source_map_at(generation, entity_id, 0, output);
}

void mock_pseudocode_worker_t::set_available(bool available) noexcept
{
    available_ = available;
}

void mock_pseudocode_worker_t::set_failure_code(std::uint64_t code) noexcept
{
    failure_code_ = code;
}

void mock_pseudocode_worker_t::set_result_status(pseudocode::pseudocode_status_t status) noexcept
{
    result_status_ = status;
}

pseudocode::pseudocode_decompile_result_t mock_pseudocode_worker_t::decompile(
    const pseudocode::pseudocode_decompile_request_t& request,
    const document_cancellation_t* cancellation)
{
    pseudocode::pseudocode_decompile_result_t result;
    result.generation = request.generation;
    result.entity_id = request.entity_id;

    if (cancellation && cancellation->cancelled()) {
        result.status = pseudocode::pseudocode_status_t::cancelled_state;
        return result;
    }

    if (!available_) {
        result.status = pseudocode::pseudocode_status_t::error_state;
        return result;
    }

    result.status = result_status_;
    result.rendered_text = "void func() {\n  return;\n}\n";
    result.total_lines = 3;
    result.total_tokens = 16;
    result.total_source_maps = 1;
    result.elapsed_ms = 1;
    return result;
}

bool mock_pseudocode_worker_t::worker_available() const noexcept
{
    return available_;
}

std::uint64_t mock_pseudocode_worker_t::last_failure_code() const noexcept
{
    return failure_code_;
}

void test_harness_t::register_test(const std::string& name, std::function<test_result_t()> test)
{
    tests_.emplace_back(name, std::move(test));
}

test_summary_t test_harness_t::run_all()
{
    test_summary_t summary;
    summary.total = tests_.size();
    for (const auto& [name, test] : tests_) {
        test_result_t result;
        const auto start = std::chrono::steady_clock::now();
        try {
            result = test();
        } catch (const std::exception& e) {
            result.passed = false;
            result.message = std::string("exception: ") + e.what();
        }
        const auto end = std::chrono::steady_clock::now();
        result.test_name = name;
        result.elapsed_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());

        if (result.passed)
            ++summary.passed;
        else
            ++summary.failed;
        summary.results.push_back(std::move(result));
    }
    return summary;
}

test_summary_t test_harness_t::run_by_name(const std::string& name)
{
    test_summary_t summary;
    summary.total = 0;
    for (const auto& [test_name, test] : tests_) {
        if (test_name != name)
            continue;
        ++summary.total;
        test_result_t result;
        const auto start = std::chrono::steady_clock::now();
        try {
            result = test();
        } catch (const std::exception& e) {
            result.passed = false;
            result.message = std::string("exception: ") + e.what();
        }
        const auto end = std::chrono::steady_clock::now();
        result.test_name = test_name;
        result.elapsed_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());

        if (result.passed)
            ++summary.passed;
        else
            ++summary.failed;
        summary.results.push_back(std::move(result));
    }
    return summary;
}

std::size_t test_harness_t::test_count() const noexcept
{
    return tests_.size();
}

test_result_t test_c03_large_virtual_model()
{
    test_result_t r{"C03_large_virtual_model", false, ""};
    mock_disasm_store_t store(1, 1000000);
    disasm::disasm_document_model_t model(store);

    document_page_request_t req;
    req.generation = 1;
    req.offset = 999900;
    req.limit = 128;

    disasm::disasm_page_t page;
    auto err = model.page(req, nullptr, page);
    if (!err.ok()) {
        r.message = "page failed: code=" + std::to_string(static_cast<unsigned>(err.code));
        return r;
    }
    if (page.instructions.size() != 100) {
        r.message = "expected 100 instructions, got " + std::to_string(page.instructions.size());
        return r;
    }
    if (page.next_offset != 1000000) {
        r.message = "next_offset mismatch: " + std::to_string(page.next_offset);
        return r;
    }
    if (page.total_instructions != 1000000) {
        r.message = "total mismatch: " + std::to_string(page.total_instructions);
        return r;
    }
    r.passed = true;
    return r;
}

test_result_t test_c04_stale_generation()
{
    test_result_t r{"C04_stale_generation", false, ""};
    mock_disasm_store_t store(2, 1000);
    disasm::disasm_document_model_t model(store);

    document_page_request_t req;
    req.generation = 1;
    req.offset = 0;
    req.limit = 16;

    disasm::disasm_page_t page;
    auto err = model.page(req, nullptr, page);
    if (err.code != document_adapter_error_code_t::stale_generation) {
        r.message = "expected stale_generation, got code=" + std::to_string(static_cast<unsigned>(err.code));
        return r;
    }
    if (err.expected != 2 || err.actual != 1) {
        r.message = "expected gen mismatch 2 vs 1";
        return r;
    }
    r.passed = true;
    return r;
}

test_result_t test_c05_overlay_visualization()
{
    test_result_t r{"C05_overlay_visualization", false, ""};
    mock_disasm_store_t store(1, 100);
    mock_disasm_overlay_t overlays;
    overlays.add_overlay(0x1000, 0x1004, document_overlay_kind_t::highlight, "entry_highlight");
    overlays.add_overlay(0x1008, 0x100C, document_overlay_kind_t::user_annotation, "note");

    disasm::disasm_document_model_t model(store, &overlays);

    document_page_request_t req;
    req.generation = 1;
    req.offset = 0;
    req.limit = 4;

    disasm::disasm_page_t page;
    auto err = model.page(req, nullptr, page);
    if (!err.ok()) {
        r.message = "page failed";
        return r;
    }
    if (page.instructions.size() != 4) {
        r.message = "expected 4 instructions, got " + std::to_string(page.instructions.size());
        return r;
    }
    if (page.instructions[0].overlay_count != 1) {
        r.message = "expected 1 overlay on instruction 0, got " + std::to_string(page.instructions[0].overlay_count);
        return r;
    }
    if (page.instructions[2].overlay_count != 1) {
        r.message = "expected 1 overlay on instruction 2, got " + std::to_string(page.instructions[2].overlay_count);
        return r;
    }
    if (page.instructions[1].overlay_count != 0) {
        r.message = "expected 0 overlays on instruction 1";
        return r;
    }

    std::vector<document_overlay_descriptor_t> listed;
    err = model.list_overlays(1, listed);
    if (!err.ok()) {
        r.message = "list_overlays failed";
        return r;
    }
    if (listed.size() != 2) {
        r.message = "expected 2 listed overlays, got " + std::to_string(listed.size());
        return r;
    }
    r.passed = true;
    return r;
}

test_result_t test_c06_cross_document_navigation()
{
    test_result_t r{"C06_cross_document_navigation", false, ""};
    mock_disasm_store_t disasm_store(1, 1000);
    mock_hex_store_t hex_store(1, 16000);

    disasm::disasm_document_model_t disasm_model(disasm_store);
    hex::hex_document_model_t hex_model(hex_store);

    document_selection_request_t sel;
    sel.generation = 1;
    sel.selection.kind = selection_kind_t::address;
    sel.selection.has_address = true;
    sel.selection.address = 0x1020;

    disasm::disasm_instruction_view_t disasm_anchor;
    auto err = disasm_model.select(sel, disasm_anchor);
    if (!err.ok()) {
        r.message = "disasm select failed";
        return r;
    }
    if (disasm_anchor.address != 0x1020) {
        r.message = "disasm anchor address mismatch: " + std::to_string(disasm_anchor.address);
        return r;
    }

    document_navigation_sync_t sync;
    sync.source_document = {1};
    sync.source_kind = document_kind_t::disassembly;
    sync.selection = sel.selection;
    sync.cursor.has_position = true;
    sync.cursor.position = disasm_anchor.ordinal;
    sync.generation = 1;
    sync.policy = view_synchronization_policy_t::cursor_and_selection;
    sync.synchronization_group = 1;

    document_navigation_proposal_t proposal;
    err = hex_model.synchronize(sync, proposal);
    if (!err.ok()) {
        r.message = "hex synchronize failed: code=" + std::to_string(static_cast<unsigned>(err.code));
        return r;
    }
    if (!proposal.cursor.has_position) {
        r.message = "hex proposal missing cursor";
        return r;
    }
    if (proposal.target_document.kind != document_kind_t::hex) {
        r.message = "hex proposal wrong document kind";
        return r;
    }
    r.passed = true;
    return r;
}

test_result_t test_c07_independent_workspace()
{
    test_result_t r{"C07_independent_workspace", false, ""};
    mock_disasm_store_t store_a(1, 100);
    mock_disasm_store_t store_b(2, 200);

    disasm::disasm_document_model_t model_a(store_a);
    disasm::disasm_document_model_t model_b(store_b);

    document_page_request_t req_a;
    req_a.generation = 1;
    req_a.offset = 0;
    req_a.limit = 10;
    disasm::disasm_page_t page_a;
    auto err = model_a.page(req_a, nullptr, page_a);
    if (!err.ok()) {
        r.message = "model_a page failed";
        return r;
    }
    if (page_a.total_instructions != 100) {
        r.message = "model_a total mismatch: " + std::to_string(page_a.total_instructions);
        return r;
    }

    document_page_request_t req_b;
    req_b.generation = 2;
    req_b.offset = 0;
    req_b.limit = 10;
    disasm::disasm_page_t page_b;
    err = model_b.page(req_b, nullptr, page_b);
    if (!err.ok()) {
        r.message = "model_b page failed";
        return r;
    }
    if (page_b.total_instructions != 200) {
        r.message = "model_b total mismatch: " + std::to_string(page_b.total_instructions);
        return r;
    }

    document_page_request_t req_b_stale;
    req_b_stale.generation = 1;
    req_b_stale.offset = 0;
    req_b_stale.limit = 10;
    disasm::disasm_page_t page_b_stale;
    err = model_b.page(req_b_stale, nullptr, page_b_stale);
    if (err.code != document_adapter_error_code_t::stale_generation) {
        r.message = "model_b should reject gen 1";
        return r;
    }
    r.passed = true;
    return r;
}

test_result_t test_c08_explicit_request_only()
{
    test_result_t r{"C08_explicit_request_only", false, ""};
    mock_pseudocode_store_t store(1);
    mock_pseudocode_worker_t worker;
    pseudocode::pseudocode_document_model_t model(store, &worker);

    if (model.auto_decompilation_enabled()) {
        r.message = "auto-decompilation should be disabled by default";
        return r;
    }

    document_page_request_t req;
    req.generation = 1;
    req.offset = 0;
    req.limit = 10;
    pseudocode::pseudocode_page_t page;
    auto err = model.page(req, nullptr, page);
    if (err.code != document_adapter_error_code_t::explicit_request_required) {
        r.message = "page without decompile should fail with explicit_request_required, got code=" +
                    std::to_string(static_cast<unsigned>(err.code));
        return r;
    }

    store.set_document_ready(42, 3);

    pseudocode::pseudocode_decompile_request_t decomp_req;
    decomp_req.generation = 1;
    decomp_req.entity_id = 42;
    decomp_req.entry_address = 0x1000;
    decomp_req.profile = 2;
    pseudocode::pseudocode_decompile_result_t decomp_result;
    err = model.request_decompilation(decomp_req, nullptr, decomp_result);
    if (!err.ok()) {
        r.message = "request_decompilation failed: code=" + std::to_string(static_cast<unsigned>(err.code));
        return r;
    }
    if (model.status() != pseudocode::pseudocode_status_t::ready) {
        r.message = "model status not ready after decompilation";
        return r;
    }
    if (model.active_entity_id() != 42) {
        r.message = "active entity id mismatch";
        return r;
    }

    err = model.page(req, nullptr, page);
    if (!err.ok()) {
        r.message = "page after decompile failed: code=" + std::to_string(static_cast<unsigned>(err.code));
        return r;
    }
    if (page.lines.size() != 3) {
        r.message = "expected 3 lines, got " + std::to_string(page.lines.size());
        return r;
    }
    r.passed = true;
    return r;
}

test_result_t test_c09_cancellation()
{
    test_result_t r{"C09_cancellation", false, ""};
    mock_disasm_store_t store(1, 10000);
    disasm::disasm_document_model_t model(store);

    flag_cancellation_t cancel(true);

    document_page_request_t req;
    req.generation = 1;
    req.offset = 0;
    req.limit = 256;
    disasm::disasm_page_t page;
    auto err = model.page(req, &cancel, page);
    if (err.code != document_adapter_error_code_t::cancelled) {
        r.message = "expected cancelled, got code=" + std::to_string(static_cast<unsigned>(err.code));
        return r;
    }
    r.passed = true;
    return r;
}

test_result_t test_c10_address_mapping()
{
    test_result_t r{"C10_address_mapping", false, ""};
    mock_disasm_store_t store(1, 1000);
    disasm::disasm_document_model_t model(store);

    disasm::disasm_instruction_view_t anchor;
    auto err = model.navigate_to_address(1, 0x1020, anchor);
    if (!err.ok()) {
        r.message = "navigate_to_address failed";
        return r;
    }
    if (anchor.ordinal != 8) {
        r.message = "ordinal mapping wrong: expected 8, got " + std::to_string(anchor.ordinal);
        return r;
    }
    if (anchor.address != 0x1020) {
        r.message = "anchor address wrong: " + std::to_string(anchor.address);
        return r;
    }
    if (!model.has_selection()) {
        r.message = "selection not set after navigate";
        return r;
    }
    if (model.cursor().position != 8) {
        r.message = "cursor position wrong: " + std::to_string(model.cursor().position);
        return r;
    }
    r.passed = true;
    return r;
}

test_result_t test_c11_stale_result()
{
    test_result_t r{"C11_stale_result", false, ""};
    mock_pseudocode_store_t store(1);
    mock_pseudocode_worker_t worker;
    worker.set_result_status(pseudocode::pseudocode_status_t::stale);
    pseudocode::pseudocode_document_model_t model(store, &worker);

    store.set_document_ready(42, 3);

    pseudocode::pseudocode_decompile_request_t decomp_req;
    decomp_req.generation = 1;
    decomp_req.entity_id = 42;
    decomp_req.entry_address = 0x1000;
    decomp_req.profile = 2;
    pseudocode::pseudocode_decompile_result_t decomp_result;
    auto err = model.request_decompilation(decomp_req, nullptr, decomp_result);
    if (err.code != document_adapter_error_code_t::stale_generation) {
        r.message = "expected stale_generation from worker stale result, got code=" +
                    std::to_string(static_cast<unsigned>(err.code));
        return r;
    }
    if (model.status() != pseudocode::pseudocode_status_t::stale) {
        r.message = "model status should be stale";
        return r;
    }
    r.passed = true;
    return r;
}

test_result_t test_c12_worker_failure()
{
    test_result_t r{"C12_worker_failure", false, ""};
    mock_pseudocode_store_t store(1);
    mock_pseudocode_worker_t worker;
    worker.set_available(false);
    worker.set_failure_code(9999);
    pseudocode::pseudocode_document_model_t model(store, &worker);

    store.set_document_ready(42, 3);

    pseudocode::pseudocode_decompile_request_t decomp_req;
    decomp_req.generation = 1;
    decomp_req.entity_id = 42;
    decomp_req.entry_address = 0x1000;
    decomp_req.profile = 2;
    pseudocode::pseudocode_decompile_result_t decomp_result;
    auto err = model.request_decompilation(decomp_req, nullptr, decomp_result);
    if (err.code != document_adapter_error_code_t::worker_failure) {
        r.message = "expected worker_failure, got code=" + std::to_string(static_cast<unsigned>(err.code));
        return r;
    }
    if (err.subject != 9999) {
        r.message = "failure code mismatch: " + std::to_string(err.subject);
        return r;
    }
    if (model.status() != pseudocode::pseudocode_status_t::error_state) {
        r.message = "model status should be error_state";
        return r;
    }
    r.passed = true;
    return r;
}

test_result_t test_c16_pseudocode_source_mapping()
{
    test_result_t r{"C16_pseudocode_source_mapping", false, ""};
    mock_pseudocode_store_t store(1);
    mock_pseudocode_worker_t worker;
    store.set_document_ready(42, 3);
    pseudocode::pseudocode_document_model_t model(store, &worker);

    pseudocode::pseudocode_decompile_request_t decomp_req;
    decomp_req.generation = 1;
    decomp_req.entity_id = 42;
    decomp_req.entry_address = 0x1000;
    pseudocode::pseudocode_decompile_result_t decomp_result;
    model.request_decompilation(decomp_req, nullptr, decomp_result);

    pseudocode::pseudocode_source_map_view_t map;
    auto err = model.map_address_to_source(1, 0x1008, map);
    if (!err.ok()) {
        r.message = "map_address_to_source failed: code=" + std::to_string(static_cast<unsigned>(err.code));
        return r;
    }
    if (!map.has_address_range) {
        r.message = "source map missing address range";
        return r;
    }
    if (map.source_path != "test.c") {
        r.message = "source path mismatch: " + map.source_path;
        return r;
    }

    err = model.map_token_to_source(1, 0, 16, map);
    if (!err.ok()) {
        r.message = "map_token_to_source failed";
        return r;
    }
    if (map.token_begin != 0 || map.token_end != 16) {
        r.message = "token range mismatch in source map";
        return r;
    }

    err = model.map_address_to_source(1, 0xFFFF, map);
    if (err.code != document_adapter_error_code_t::missing_entity) {
        r.message = "expected missing_entity for out-of-range address";
        return r;
    }
    r.passed = true;
    return r;
}

test_result_t test_c17_hex_disasm_sync()
{
    test_result_t r{"C17_hex_disasm_sync", false, ""};
    mock_disasm_store_t disasm_store(1, 1000);
    mock_hex_store_t hex_store(1, 16000);

    disasm::disasm_document_model_t disasm_model(disasm_store);
    hex::hex_document_model_t hex_model(hex_store);

    document_navigation_sync_t sync_to_hex;
    sync_to_hex.source_document = {1};
    sync_to_hex.source_kind = document_kind_t::disassembly;
    sync_to_hex.selection.kind = selection_kind_t::address;
    sync_to_hex.selection.has_address = true;
    sync_to_hex.selection.address = 0x1010;
    sync_to_hex.cursor.has_position = true;
    sync_to_hex.cursor.position = 4;
    sync_to_hex.generation = 1;
    sync_to_hex.policy = view_synchronization_policy_t::selection;
    sync_to_hex.synchronization_group = 1;

    document_navigation_proposal_t hex_proposal;
    auto err = hex_model.synchronize(sync_to_hex, hex_proposal);
    if (!err.ok()) {
        r.message = "hex synchronize from disasm failed: code=" + std::to_string(static_cast<unsigned>(err.code));
        return r;
    }
    if (!hex_proposal.cursor.has_position) {
        r.message = "hex proposal missing cursor";
        return r;
    }
    const std::uint64_t expected_row = (0x1010 - 0x1000) / hex::k_hex_bytes_per_row;
    if (hex_proposal.cursor.position != expected_row) {
        r.message = "hex cursor position mismatch: expected " + std::to_string(expected_row) +
                    " got " + std::to_string(hex_proposal.cursor.position);
        return r;
    }
    if (!hex_model.has_selection()) {
        r.message = "hex model should have selection after sync";
        return r;
    }

    document_navigation_sync_t sync_to_disasm;
    sync_to_disasm.source_document = {2};
    sync_to_disasm.source_kind = document_kind_t::hex;
    sync_to_disasm.selection.kind = selection_kind_t::address;
    sync_to_disasm.selection.has_address = true;
    sync_to_disasm.selection.address = 0x1020;
    sync_to_disasm.cursor.has_position = true;
    sync_to_disasm.cursor.position = 2;
    sync_to_disasm.generation = 1;
    sync_to_disasm.policy = view_synchronization_policy_t::cursor_and_selection;
    sync_to_disasm.synchronization_group = 1;

    document_navigation_proposal_t disasm_proposal;
    err = disasm_model.synchronize(sync_to_disasm, disasm_proposal);
    if (!err.ok()) {
        r.message = "disasm synchronize from hex failed";
        return r;
    }
    if (disasm_proposal.cursor.position != 8) {
        r.message = "disasm cursor position mismatch: expected 8, got " + std::to_string(disasm_proposal.cursor.position);
        return r;
    }
    r.passed = true;
    return r;
}

test_result_t test_c20_overlay_listing()
{
    test_result_t r{"C20_overlay_listing", false, ""};
    mock_hex_store_t store(1, 16000);

    hex::hex_document_model_t model(store);

    std::vector<document_overlay_descriptor_t> overlays;
    auto err = model.list_overlays(1, overlays);
    if (!err.ok()) {
        r.message = "list_overlays with no adapter should succeed with empty";
        return r;
    }
    if (!overlays.empty()) {
        r.message = "expected empty overlay list with no adapter";
        return r;
    }

    err = model.list_overlays(2, overlays);
    if (err.code != document_adapter_error_code_t::stale_generation) {
        r.message = "expected stale_generation for gen 2";
        return r;
    }

    document_page_request_t req;
    req.generation = 1;
    req.offset = 0;
    req.limit = 16;
    hex::hex_page_t page;
    err = model.page(req, nullptr, page);
    if (!err.ok()) {
        r.message = "hex page failed";
        return r;
    }
    if (page.rows.empty()) {
        r.message = "expected at least 1 row";
        return r;
    }
    if (page.rows[0].byte_count != hex::k_hex_bytes_per_row) {
        r.message = "first row should have 16 bytes, got " + std::to_string(page.rows[0].byte_count);
        return r;
    }
    if (page.rows[0].ascii[0] == '\0') {
        r.message = "ascii should not be empty";
        return r;
    }
    r.passed = true;
    return r;
}

void register_all_workbench_document_tests(test_harness_t& harness)
{
    harness.register_test("C03_large_virtual_model", test_c03_large_virtual_model);
    harness.register_test("C04_stale_generation", test_c04_stale_generation);
    harness.register_test("C05_overlay_visualization", test_c05_overlay_visualization);
    harness.register_test("C06_cross_document_navigation", test_c06_cross_document_navigation);
    harness.register_test("C07_independent_workspace", test_c07_independent_workspace);
    harness.register_test("C08_explicit_request_only", test_c08_explicit_request_only);
    harness.register_test("C09_cancellation", test_c09_cancellation);
    harness.register_test("C10_address_mapping", test_c10_address_mapping);
    harness.register_test("C11_stale_result", test_c11_stale_result);
    harness.register_test("C12_worker_failure", test_c12_worker_failure);
    harness.register_test("C16_pseudocode_source_mapping", test_c16_pseudocode_source_mapping);
    harness.register_test("C17_hex_disasm_sync", test_c17_hex_disasm_sync);
    harness.register_test("C20_overlay_listing", test_c20_overlay_listing);
}

test_summary_t run_all_workbench_document_tests()
{
    test_harness_t harness;
    register_all_workbench_document_tests(harness);
    return harness.run_all();
}

}
