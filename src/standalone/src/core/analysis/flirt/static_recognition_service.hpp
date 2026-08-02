#pragma once

#include "flirt_engine.hpp"

#include "../decompiler/type_graph_builder.hpp"
#include "../workspace/analysis_workspace.hpp"
#include "../workspace/byte_provider.hpp"
#include "../workspace/workspace_types.hpp"
#include "../../re/rtti.hpp"
#include "../../re/vmt.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace aida::analysis::static_recognition {

inline constexpr std::uint8_t k_status_pending = 0;
inline constexpr std::uint8_t k_status_running = 1;
inline constexpr std::uint8_t k_status_complete = 2;
inline constexpr std::uint8_t k_status_partial = 3;
inline constexpr std::uint8_t k_status_failed = 4;
inline constexpr std::uint8_t k_status_db_absent = 5;
inline constexpr std::uint8_t k_status_no_rtti = 6;

struct name_out_t {
    std::uint64_t rva = 0;
    std::string name;
    std::string kind;
    std::uint8_t confidence = 0;
    std::string source;
};

struct prototype_out_t {
    std::uint64_t rva = 0;
    std::string name;
    std::string prototype_text;
    bool is_noreturn = false;
    std::uint8_t confidence = 0;
};

struct vtable_slot_out_t {
    std::uint64_t vtable_rva = 0;
    std::uint64_t slot_index = 0;
    std::uint64_t function_rva = 0;
    std::string method_name;
    std::string class_name;
    std::uint8_t confidence = 0;
};

struct recognition_records_t {
    std::uint64_t revision = 0;
    std::uint64_t generation = 0;
    std::vector<flirt::flirt_match_t> flirt;
    re::rtti::static_rtti_result_t rtti;
    re::vmt::static_vtable_slots_result_t vtables;
    std::vector<name_out_t> names;
    std::vector<prototype_out_t> prototypes;
    std::vector<vtable_slot_out_t> vtable_slots;
    std::uint8_t status = k_status_pending;
    std::uint8_t flirt_status = flirt::k_flirt_status_invalid;
    std::string db_toolset;
    std::uint64_t dropped_records = 0;
    double elapsed_ms_flirt = 0.0;
    double elapsed_ms_rtti = 0.0;
    double elapsed_ms_vmt = 0.0;
};

struct static_recognition_settings_t {
    bool enable_flirt = true;
    bool enable_rtti = true;
    bool enable_vmt = true;
    flirt::flirt_scan_limits_t flirt_limits;
    re::rtti::static_rtti_limits_t rtti_limits;
    std::string db_path;
};

void ensure_attached(const std::shared_ptr<analysis_workspace_t>& workspace);

workspace_result_t<std::shared_ptr<const recognition_records_t>>
run_for_workspace(std::shared_ptr<analysis_workspace_t> workspace,
                  const static_recognition_settings_t& settings,
                  const cancellation_token_t& cancel);

std::shared_ptr<const recognition_records_t>
records_for(const std::shared_ptr<analysis_workspace_t>& workspace);

std::vector<type_graph::type_seed_batch_t>
type_seed_batches_for(const std::shared_ptr<analysis_workspace_t>& workspace,
                      const decompiler_entity_key_t& entity,
                      std::uint64_t generation,
                      std::uint8_t min_confidence);

}
