#pragma once

#include "../disasm_document.hpp"
#include "../hex_document.hpp"
#include "../pseudocode_document.hpp"
#include "../document_adapter_base.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace aida::workbench::adapters::test {

struct test_result_t {
    std::string test_name;
    bool passed = false;
    std::string message;
    std::uint64_t elapsed_ms = 0;
};

struct test_summary_t {
    std::size_t total = 0;
    std::size_t passed = 0;
    std::size_t failed = 0;
    std::vector<test_result_t> results;
};

class flag_cancellation_t final : public document_cancellation_t {
public:
    explicit flag_cancellation_t(bool initial = false) noexcept : flag_(initial) {}
    void set_cancelled(bool value) noexcept { flag_ = value; }
    bool cancelled() const noexcept override { return flag_.load(std::memory_order_acquire); }
private:
    std::atomic<bool> flag_;
};

class mock_disasm_store_t final : public disasm::disasm_packed_store_adapter_t {
public:
    mock_disasm_store_t(std::uint64_t generation, std::uint64_t instruction_count);
    void advance_generation() noexcept;
    std::uint64_t current_generation() const noexcept override;
    bool generation_current(std::uint64_t generation) const noexcept override;
    std::uint64_t instruction_count(std::uint64_t generation) const noexcept override;
    bool instruction_at(std::uint64_t generation, std::uint64_t ordinal,
                       disasm::disasm_instruction_view_t& output) const override;
    bool instruction_by_address(std::uint64_t generation, std::uint64_t address,
                               disasm::disasm_instruction_view_t& output) const override;
    std::uint64_t ordinal_for_address(std::uint64_t generation,
                                      std::uint64_t address) const noexcept override;
    std::string mnemonic_storage;
    std::string operands_storage;
private:
    std::uint64_t generation_;
    std::uint64_t instruction_count_;
};

class mock_disasm_overlay_t final : public disasm::disasm_overlay_adapter_t {
public:
    void add_overlay(std::uint64_t address, std::uint64_t address_end,
                     document_overlay_kind_t kind, const std::string& name);
    std::uint64_t overlay_revision(std::uint64_t generation) const noexcept override;
    std::size_t overlay_count(std::uint64_t generation) const noexcept override;
    bool overlay_at(std::uint64_t generation, std::size_t ordinal,
                   disasm::disasm_overlay_entry_t& output) const override;
    bool overlays_in_range(std::uint64_t generation, std::uint64_t address_begin,
                           std::uint64_t address_end,
                           std::vector<disasm::disasm_overlay_entry_t>& output) const override;
private:
    std::vector<disasm::disasm_overlay_entry_t> entries_;
};

class mock_hex_store_t final : public hex::hex_packed_store_adapter_t {
public:
    mock_hex_store_t(std::uint64_t generation, std::uint64_t byte_count);
    void advance_generation() noexcept;
    std::uint64_t current_generation() const noexcept override;
    bool generation_current(std::uint64_t generation) const noexcept override;
    std::uint64_t byte_count(std::uint64_t generation) const noexcept override;
    bool bytes_at(std::uint64_t generation, std::uint64_t offset,
                 std::uint8_t* buffer, std::uint8_t max_count,
                 std::uint8_t& actual_count) const override;
    std::uint64_t base_address_for_offset(std::uint64_t generation,
                                           std::uint64_t offset) const noexcept override;
    std::uint64_t offset_for_address(std::uint64_t generation,
                                     std::uint64_t address) const noexcept override;
private:
    std::uint64_t generation_;
    std::uint64_t byte_count_;
};

class mock_pseudocode_store_t final : public pseudocode::pseudocode_packed_store_adapter_t {
public:
    mock_pseudocode_store_t(std::uint64_t generation);
    void set_document_ready(std::uint64_t entity_id, std::uint64_t line_count);
    void advance_generation() noexcept;
    std::uint64_t current_generation() const noexcept override;
    bool generation_current(std::uint64_t generation) const noexcept override;
    pseudocode::pseudocode_status_t document_status(std::uint64_t generation,
                                                     std::uint64_t entity_id) const noexcept override;
    std::uint64_t line_count(std::uint64_t generation, std::uint64_t entity_id) const noexcept override;
    std::uint64_t token_count(std::uint64_t generation, std::uint64_t entity_id) const noexcept override;
    std::uint64_t source_map_count(std::uint64_t generation, std::uint64_t entity_id) const noexcept override;
    std::uint64_t diagnostic_count(std::uint64_t generation, std::uint64_t entity_id) const noexcept override;
    bool line_at(std::uint64_t generation, std::uint64_t entity_id,
                 std::uint64_t ordinal, pseudocode::pseudocode_line_view_t& output) const override;
    bool token_at(std::uint64_t generation, std::uint64_t entity_id,
                  std::uint64_t ordinal, pseudocode::pseudocode_token_view_t& output) const override;
    bool source_map_at(std::uint64_t generation, std::uint64_t entity_id,
                       std::uint64_t ordinal, pseudocode::pseudocode_source_map_view_t& output) const override;
    bool diagnostic_at(std::uint64_t generation, std::uint64_t entity_id,
                       std::uint64_t ordinal, pseudocode::pseudocode_diagnostic_view_t& output) const override;
    bool source_map_for_address(std::uint64_t generation, std::uint64_t entity_id,
                                std::uint64_t address,
                                pseudocode::pseudocode_source_map_view_t& output) const override;
    bool source_map_for_token_range(std::uint64_t generation, std::uint64_t entity_id,
                                    std::uint32_t token_begin, std::uint32_t token_end,
                                    pseudocode::pseudocode_source_map_view_t& output) const override;
private:
    std::uint64_t generation_;
    std::uint64_t ready_entity_id_;
    std::uint64_t ready_line_count_;
    std::string text_storage_;
};

class mock_pseudocode_worker_t final : public pseudocode::pseudocode_decompile_worker_adapter_t {
public:
    void set_available(bool available) noexcept;
    void set_failure_code(std::uint64_t code) noexcept;
    void set_result_status(pseudocode::pseudocode_status_t status) noexcept;
    pseudocode::pseudocode_decompile_result_t decompile(
        const pseudocode::pseudocode_decompile_request_t& request,
        const document_cancellation_t* cancellation) override;
    bool worker_available() const noexcept override;
    std::uint64_t last_failure_code() const noexcept override;
private:
    bool available_ = true;
    std::uint64_t failure_code_ = 0;
    pseudocode::pseudocode_status_t result_status_ = pseudocode::pseudocode_status_t::ready;
};

class test_harness_t {
public:
    void register_test(const std::string& name, std::function<test_result_t()> test);
    test_summary_t run_all();
    test_summary_t run_by_name(const std::string& name);
    std::size_t test_count() const noexcept;
private:
    std::vector<std::pair<std::string, std::function<test_result_t()>>> tests_;
};

void register_all_workbench_document_tests(test_harness_t& harness);
test_summary_t run_all_workbench_document_tests();

test_result_t test_c03_large_virtual_model();
test_result_t test_c04_stale_generation();
test_result_t test_c05_overlay_visualization();
test_result_t test_c06_cross_document_navigation();
test_result_t test_c07_independent_workspace();
test_result_t test_c08_explicit_request_only();
test_result_t test_c09_cancellation();
test_result_t test_c10_address_mapping();
test_result_t test_c11_stale_result();
test_result_t test_c12_worker_failure();
test_result_t test_c16_pseudocode_source_mapping();
test_result_t test_c17_hex_disasm_sync();
test_result_t test_c20_overlay_listing();

}
