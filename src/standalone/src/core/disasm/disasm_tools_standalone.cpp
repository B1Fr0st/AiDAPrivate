#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "standalone_compat.hpp"
#include "zydis_disasm.hpp"
#include "disasm_view.hpp"
#include "function_index.hpp"
#include "xref_db.hpp"
#include "xref_engine.hpp"
#include "pe_parser.hpp"
#include "hex_view.hpp"
#include "standalone_driver.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"
#include "../analysis/workspace/live_snapshot_provider.hpp"
#include "../analysis/workspace/overlay_journal.hpp"
#include "../analysis/workspace/search_index.hpp"

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace disasm_tools {

static constexpr uint64_t kMaxResolvedFunctionBytes = 1024ull * 1024ull;
static constexpr uint64_t kMaxLiveFunctionDisasmBytes = 256ull * 1024ull;
static constexpr int kMaxTotalDisasmInstructions = 8192;

static std::string hex_u64(uint64_t value)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
    return buf;
}

static bool parse_address_param(const json& params, const char* key, uint64_t& out)
{
    if (!params.contains(key))
        return false;
    const auto& v = params[key];
    if (v.is_string()) {
        auto parsed = sa_parse_address(v.get<std::string>());
        if (!parsed) return false;
        out = *parsed;
        return true;
    }
    if (v.is_number_unsigned()) {
        out = v.get<uint64_t>();
        return true;
    }
    if (v.is_number_integer()) {
        int64_t s = v.get<int64_t>();
        if (s < 0) return false;
        out = static_cast<uint64_t>(s);
        return true;
    }
    return false;
}

static std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static std::string bytes_to_hex(const uint8_t* data, int len)
{
    if (len <= 0) return std::string();
    std::string out;
    out.reserve(static_cast<size_t>(len) * 3);
    char buf[4];
    for (int i = 0; i < len; ++i) {
        std::snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned>(data[i]));
        if (i > 0) out.push_back(' ');
        out.append(buf, 2);
    }
    return out;
}

static json instruction_to_json(const AsmInstr& ins)
{
    json entry;
    entry["address"]  = hex_u64(ins.addr);
    entry["mnemonic"] = std::string(ins.mnem);
    entry["operands"] = std::string(ins.ops);
    entry["length"]   = ins.len;
    entry["bytes"]    = bytes_to_hex(ins.raw, std::min(ins.len, 15));
    entry["is_branch"] = ins.is_branch;
    entry["is_call"]   = ins.is_call;
    entry["is_ret"]    = ins.is_ret;
    return entry;
}






static bool parse_hex_pattern(const std::string& in, std::vector<uint8_t>& bytes,
                              std::vector<bool>& wildmask)
{
    bytes.clear();
    wildmask.clear();
    std::string cur;
    auto flush = [&](const std::string& tok) -> bool {
        if (tok.empty()) return true;
        if (tok == "??" || tok == "?") {
            bytes.push_back(0);
            wildmask.push_back(true);
            return true;
        }
        if (tok.size() != 2) return false;
        auto hex_nibble = [](char c, int& out) -> bool {
            if (c >= '0' && c <= '9') { out = c - '0'; return true; }
            if (c >= 'a' && c <= 'f') { out = 10 + (c - 'a'); return true; }
            if (c >= 'A' && c <= 'F') { out = 10 + (c - 'A'); return true; }
            return false;
        };
        int hi = 0, lo = 0;
        if (!hex_nibble(tok[0], hi) || !hex_nibble(tok[1], lo))
            return false;
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
        wildmask.push_back(false);
        return true;
    };
    for (char c : in) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',') {
            if (!flush(cur)) return false;
            cur.clear();
            continue;
        }
        cur.push_back(c);
        if (cur.size() == 2) {
            if (!flush(cur)) return false;
            cur.clear();
        }
    }
    if (!cur.empty() && !flush(cur)) return false;
    return !bytes.empty();
}

using workspace_ptr_t = std::shared_ptr<aida::analysis::analysis_workspace_t>;

static tool_result_t workspace_failure(const aida::analysis::workspace_error_t& error)
{
    json details{{"phase", error.phase}, {"cancelled", error.cancellation},
                 {"deadline", error.deadline}};
    if (error.offset) details["offset"] = *error.offset;
    if (error.size) details["size"] = *error.size;
    return tool_result_t::error(error.message, error.stable_code(), details);
}

static tool_result_t workspace_error(std::string message, std::string code)
{
    return tool_result_t::error(message, code, json::object());
}

static uint64_t workspace_va(const workspace_ptr_t& workspace,
                             const aida::analysis::address_t& address)
{
    return function_index::workspace_display_address(workspace, address);
}

static aida::analysis::address_t workspace_address(const workspace_ptr_t& workspace,
                                                    uint64_t value)
{
    aida::analysis::address_t address;
    address.space = workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot
        ? aida::analysis::address_space_id_t::live_virtual
        : aida::analysis::address_space_id_t::virtual_address;
    address.value = value;
    address.architecture = workspace->identity().architecture();
    if (auto image = workspace->image()) {
        address.mode = image->architecture_mode();
        if (workspace->target_kind() == aida::analysis::target_kind_t::static_file &&
            value < image->image_base() && value < image->image_size())
            address.value = image->image_base() + value;
    }
    return address;
}

static bool workspace_provider_offset(const workspace_ptr_t& workspace,
                                      uint64_t address, uint64_t size, uint64_t& offset)
{
    if (workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot) {
        auto live = std::dynamic_pointer_cast<const aida::analysis::live_snapshot_provider_t>(
            workspace->provider_handle());
        if (!live || address < live->metadata().capture_address ||
            size > live->metadata().capture_size ||
            address - live->metadata().capture_address > live->metadata().capture_size - size)
            return false;
        offset = address - live->metadata().capture_address;
        return true;
    }
    auto image = workspace->image();
    if (!image) return false;
    auto rva = image->va_to_rva(address);
    if (!rva) return false;
    auto mapped = image->rva_to_file_offset(rva.value(), size);
    if (!mapped) return false;
    offset = mapped.value();
    return true;
}

static std::string workspace_overlay_text(const workspace_ptr_t& workspace,
                                          aida::analysis::overlay_operation_kind_t kind,
                                          uint64_t address)
{
    auto overlay = workspace->overlay();
    if (!overlay) return {};
    for (const auto& item : overlay->snapshot().items) {
        const auto& operation = item.second;
        if (operation.kind == kind && operation.address.value == address)
            return kind == aida::analysis::overlay_operation_kind_t::name
                ? operation.name : operation.text;
    }
    return {};
}

static json workspace_instruction_to_json(const workspace_ptr_t& workspace,
                                          const AsmInstr& instruction)
{
    json result = instruction_to_json(instruction);
    std::string comment = workspace_overlay_text(
        workspace, aida::analysis::overlay_operation_kind_t::comment, instruction.addr);
    if (!comment.empty()) result["comment"] = std::move(comment);
    return result;
}

static std::string workspace_function_name(
    const workspace_ptr_t& workspace,
    const aida::analysis::analysis_snapshot_t& snapshot,
    const aida::analysis::function_record_t& function, uint64_t address)
{
    std::string overlay = workspace_overlay_text(
        workspace, aida::analysis::overlay_operation_kind_t::name, address);
    if (!overlay.empty()) return overlay;
    if (function.symbol_id) {
        auto symbol = std::find_if(snapshot.symbols.begin(), snapshot.symbols.end(),
            [&](const auto& candidate) { return candidate.id == *function.symbol_id; });
        if (symbol != snapshot.symbols.end() && !symbol->name.empty()) return symbol->name;
    }
    return function_index::synthetic_name(workspace, workspace_address(workspace, address));
}

static const aida::analysis::function_record_t* workspace_function_for(
    const workspace_ptr_t& workspace, uint64_t address,
    std::shared_ptr<const aida::analysis::analysis_snapshot_t>& snapshot)
{
    snapshot = workspace->snapshot();
    auto image = workspace->image();
    if (!snapshot || !image) return nullptr;
    for (const auto& function : snapshot->functions) {
        const uint64_t start = workspace_va(workspace, function.start);
        const uint64_t end = workspace_va(workspace, function.end);
        if (address >= start && address < end) return &function;
    }
    return nullptr;
}

static bool workspace_live_function_for(const workspace_ptr_t& workspace,
                                        uint64_t address, uint64_t& start, uint64_t& end)
{
    auto image = workspace->image();
    if (!image || address < image->image_base()) return false;
    const uint64_t rva = address - image->image_base();
    for (const auto& runtime : image->runtime_functions()) {
        if (rva >= runtime.begin_rva && rva < runtime.end_rva) {
            start = image->image_base() + runtime.begin_rva;
            end = image->image_base() + runtime.end_rva;
            return end > start;
        }
    }
    return false;
}

static tool_result_t workspace_instruction_result(const workspace_ptr_t& workspace,
                                                  uint64_t address)
{
    auto image = workspace->image();
    if (!image) return workspace_error("Workspace image metadata is unavailable", "WORKSPACE_NOT_READY");
    auto snapshot = workspace->snapshot();
    if (snapshot) {
        auto iterator = std::lower_bound(snapshot->instructions.begin(), snapshot->instructions.end(), address,
            [&](const auto& instruction, uint64_t requested) {
                return workspace_va(workspace, instruction.address) < requested;
            });
        if (iterator != snapshot->instructions.end() && workspace_va(workspace, iterator->address) == address) {
            const size_t index = static_cast<size_t>(iterator - snapshot->instructions.begin());
            auto page = disasm::format_page(workspace, index, 1, workspace->cancellation_token());
            if (!page) return workspace_failure(page.error());
            AsmInstr formatted = page.value().front();
            uint64_t provider_offset = 0;
            if (workspace_provider_offset(workspace, address, iterator->length, provider_offset)) {
                auto bytes = workspace->provider().read_vector(provider_offset, iterator->length, 15,
                                                               workspace->cancellation_token());
                if (bytes) {
                    const size_t count = (std::min)(bytes.value().size(), sizeof(formatted.raw));
                    std::memcpy(formatted.raw, bytes.value().data(), count);
                }
            }
            json result = workspace_instruction_to_json(workspace, formatted);
            result["source"] = "workspace_snapshot";
            result["provenance"] = static_cast<unsigned>(iterator->provenance);
            result["confidence"] = iterator->confidence;
            return tool_result_t::ok(result);
        }
    }
    uint64_t provider_offset = 0;
    if (!workspace_provider_offset(workspace, address, 1, provider_offset))
        return workspace_error("Address is outside the immutable workspace byte provider", "OUT_OF_RANGE");
    const uint64_t available = (std::min<std::uint64_t>)(15, workspace->provider().size() - provider_offset);
    auto bytes = workspace->provider().read_vector(provider_offset, available, 15,
                                                   workspace->cancellation_token());
    if (!bytes) return workspace_failure(bytes.error());
    AsmInstr decoded = zydis_decode_one(bytes.value().data(), static_cast<int>(bytes.value().size()),
        address, image->architecture() == aida::analysis::architecture_id_t::x86_64);
    json result = workspace_instruction_to_json(workspace, decoded);
    result["source"] = workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot
        ? "immutable_live_snapshot" : "workspace_provider";
    return tool_result_t::ok(result);
}

static tool_result_t workspace_get_instruction(const json& params, const workspace_ptr_t& workspace)
{
    uint64_t address = 0;
    if (!parse_address_param(params, "address", address)) return tool_result_t::error("'address' is required.");
    return workspace_instruction_result(workspace, workspace_address(workspace, address).value);
}

static tool_result_t workspace_get_function_bounds(const json& params, const workspace_ptr_t& workspace)
{
    uint64_t requested = 0;
    if (!parse_address_param(params, "address", requested)) return tool_result_t::error("'address' is required.");
    const uint64_t address = workspace_address(workspace, requested).value;
    auto image = workspace->image();
    if (!image) return workspace_error("Workspace image metadata is unavailable", "WORKSPACE_NOT_READY");
    std::shared_ptr<const aida::analysis::analysis_snapshot_t> snapshot;
    const auto* function = workspace_function_for(workspace, address, snapshot);
    uint64_t start = 0, end = 0, entity_id = 0;
    std::string name, source;
    unsigned confidence = 0;
    if (function) {
        start = workspace_va(workspace, function->start);
        end = workspace_va(workspace, function->end);
        name = workspace_function_name(workspace, *snapshot, *function, start);
        source = "workspace_function_index";
        entity_id = function->id;
        confidence = function->confidence;
    } else if (workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot &&
               workspace_live_function_for(workspace, address, start, end)) {
        name = function_index::synthetic_name(workspace, workspace_address(workspace, start));
        source = "immutable_live_unwind";
        confidence = 100;
    } else {
        return workspace_error("No function found containing this address.", "FUNCTION_NOT_FOUND");
    }
    const auto* section = image->section_for_rva(start - image->image_base());
    return tool_result_t::ok(json{{"start", hex_u64(start)}, {"end", hex_u64(end)},
        {"size", end - start}, {"name", name}, {"section", section ? section->name : std::string()},
        {"module", workspace->identity().bin_name()}, {"source", source}, {"bounds_source", source},
        {"bounds_cache_hit", function != nullptr}, {"function_size_capped", false},
        {"function_size_cap", kMaxResolvedFunctionBytes}, {"uncapped_end", hex_u64(end)},
        {"uncapped_size", end - start}, {"entity_id", entity_id}, {"confidence", confidence}});
}

static tool_result_t workspace_get_function_disassembly(const json& params,
                                                        const workspace_ptr_t& workspace)
{
    uint64_t requested = 0;
    if (!parse_address_param(params, "address", requested)) return tool_result_t::error("'address' is required.");
    const uint64_t address = workspace_address(workspace, requested).value;
    size_t max_instructions = 256;
    if (params.contains("max_instrs") && params["max_instrs"].is_number_integer()) {
        const auto value = params["max_instrs"].get<int64_t>();
        if (value > 0 && value <= 8192) max_instructions = static_cast<size_t>(value);
    }
    auto image = workspace->image();
    std::shared_ptr<const aida::analysis::analysis_snapshot_t> snapshot;
    const auto* function = workspace_function_for(workspace, address, snapshot);
    if (!function || !snapshot || !image) {
        if (workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot && image) {
            uint64_t start = 0;
            uint64_t end = 0;
            if (!workspace_live_function_for(workspace, address, start, end))
                return workspace_error("No unwind-backed live function contains this address.",
                                       "FUNCTION_NOT_FOUND");
            const uint64_t span = (std::min<uint64_t>)(end - start,
                (std::min<uint64_t>)(kMaxLiveFunctionDisasmBytes,
                    (std::max<uint64_t>)(4096, static_cast<uint64_t>(max_instructions) * 16)));
            uint64_t provider_offset = 0;
            if (!workspace_provider_offset(workspace, start, span, provider_offset))
                return workspace_error("Recovered live function exceeds the immutable capture",
                                       "OUT_OF_RANGE");
            auto bytes = workspace->provider().read_vector(provider_offset, span,
                                                           kMaxLiveFunctionDisasmBytes,
                                                           workspace->cancellation_token());
            if (!bytes) return workspace_failure(bytes.error());
            json instructions = json::array();
            size_t offset = 0;
            size_t total = 0;
            while (offset < bytes.value().size() && start + offset < end &&
                   total < static_cast<size_t>(kMaxTotalDisasmInstructions)) {
                if (workspace->cancellation_token().stop_requested() || mcp_standalone::current_call_cancelled())
                    return workspace_error("Live function decode was cancelled", "CANCELLED");
                const int available = static_cast<int>((std::min<size_t>)(15, bytes.value().size() - offset));
                AsmInstr decoded = zydis_decode_one(bytes.value().data() + offset, available,
                    start + offset, image->architecture() == aida::analysis::architecture_id_t::x86_64);
                const size_t length = static_cast<size_t>((std::max)(1, decoded.len));
                if (offset + length > bytes.value().size()) break;
                if (instructions.size() < max_instructions)
                    instructions.push_back(workspace_instruction_to_json(workspace, decoded));
                ++total;
                offset += length;
            }
            const auto* section = image->section_for_rva(start - image->image_base());
            return tool_result_t::ok(json{{"function_start", hex_u64(start)},
                {"function_end", hex_u64(end)}, {"function_name", function_index::synthetic_name(
                    workspace, workspace_address(workspace, start))},
                {"module", workspace->identity().bin_name()},
                {"section", section ? section->name : std::string()}, {"source", "immutable_live_unwind"},
                {"bounds_source", "immutable_live_unwind"}, {"bounds_cache_hit", false},
                {"instruction_count", instructions.size()}, {"returned_instruction_count", instructions.size()},
                {"total_instruction_count", total}, {"total_instruction_count_exact", start + offset >= end},
                {"max_instrs", max_instructions}, {"decode_instruction_cap", kMaxTotalDisasmInstructions},
                {"decode_byte_limit", span}, {"decode_bytes_read", bytes.value().size()},
                {"decode_byte_truncated", span < end - start}, {"function_size_capped", false},
                {"function_size_cap", kMaxResolvedFunctionBytes}, {"uncapped_function_end", hex_u64(end)},
                {"uncapped_function_size", end - start}, {"truncated", instructions.size() < total || span < end - start},
                {"instructions", std::move(instructions)}});
        }
        return workspace_error("No function found containing this address.", "FUNCTION_NOT_FOUND");
    }
    const uint64_t start = workspace_va(workspace, function->start);
    const uint64_t end = workspace_va(workspace, function->end);
    auto first = std::lower_bound(snapshot->instructions.begin(), snapshot->instructions.end(), start,
        [&](const auto& instruction, uint64_t value) { return workspace_va(workspace, instruction.address) < value; });
    const size_t first_index = static_cast<size_t>(first - snapshot->instructions.begin());
    size_t total = 0;
    for (auto iterator = first; iterator != snapshot->instructions.end(); ++iterator) {
        if (workspace_va(workspace, iterator->address) >= end || total >= kMaxTotalDisasmInstructions) break;
        if ((total & 0x3FFu) == 0 &&
            (workspace->cancellation_token().stop_requested() || mcp_standalone::current_call_cancelled()))
            return workspace_error("Function instruction scan was cancelled", "CANCELLED");
        ++total;
    }
    const size_t returned = (std::min)(total, max_instructions);
    json instructions = json::array();
    constexpr size_t format_chunk_size = 256;
    for (size_t formatted_offset = 0; formatted_offset < returned;
         formatted_offset += format_chunk_size) {
        if (workspace->cancellation_token().stop_requested() || mcp_standalone::current_call_cancelled())
            return workspace_error("Function formatting was cancelled", "CANCELLED");
        const size_t chunk = (std::min)(format_chunk_size, returned - formatted_offset);
        auto formatted = disasm::format_page(workspace, first_index + formatted_offset, chunk,
                                             workspace->cancellation_token());
        if (!formatted) return workspace_failure(formatted.error());
        for (const auto& instruction : formatted.value())
            instructions.push_back(workspace_instruction_to_json(workspace, instruction));
    }
    const std::string name = workspace_function_name(workspace, *snapshot, *function, start);
    const auto* section = image->section_for_rva(start - image->image_base());
    json result;
    result["function_start"] = hex_u64(start);
    result["function_end"] = hex_u64(end);
    result["function_name"] = name;
    result["module"] = workspace->identity().bin_name();
    result["section"] = section ? section->name : std::string();
    result["source"] = "workspace_function_index";
    result["bounds_source"] = "workspace_function_index";
    result["bounds_cache_hit"] = true;
    result["instruction_count"] = returned;
    result["returned_instruction_count"] = returned;
    result["total_instruction_count"] = total;
    result["total_instruction_count_exact"] = total < static_cast<size_t>(kMaxTotalDisasmInstructions);
    result["max_instrs"] = max_instructions;
    result["decode_instruction_cap"] = kMaxTotalDisasmInstructions;
    result["decode_byte_limit"] = 0;
    result["decode_bytes_read"] = 0;
    result["decode_byte_truncated"] = false;
    result["function_size_capped"] = false;
    result["function_size_cap"] = kMaxResolvedFunctionBytes;
    result["uncapped_function_end"] = hex_u64(end);
    result["uncapped_function_size"] = end - start;
    result["truncated"] = returned < total;
    result["instructions"] = std::move(instructions);
    return tool_result_t::ok(result);
}

static tool_result_t workspace_list_functions(const json& params, const workspace_ptr_t& workspace)
{
    if (workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot)
        return workspace_error("Whole-target function listing is not supported for live snapshots",
                               "LIVE_TARGET_BULK_ANALYSIS_UNSUPPORTED");
    auto snapshot = workspace->snapshot();
    auto image = workspace->image();
    if (!snapshot || !image) return workspace_error("Workspace analysis is not ready", "WORKSPACE_NOT_READY");
    const std::string filter = params.contains("filter") && params["filter"].is_string()
        ? lower_copy(params["filter"].get<std::string>()) : std::string();
    const size_t offset = params.contains("offset") && params["offset"].is_number_unsigned()
        ? params["offset"].get<size_t>() : 0;
    size_t limit = 200;
    if (params.contains("limit") && params["limit"].is_number_unsigned())
        limit = (std::min<size_t>)(5000, (std::max<size_t>)(1, params["limit"].get<size_t>()));
    json functions = json::array();
    size_t total = 0;
    size_t visited = 0;
    for (const auto& function : snapshot->functions) {
        if ((visited++ & 0x3FFu) == 0 &&
            (workspace->cancellation_token().stop_requested() || mcp_standalone::current_call_cancelled()))
            return workspace_error("Function listing was cancelled", "CANCELLED");
        const uint64_t start = workspace_va(workspace, function.start);
        const uint64_t end = workspace_va(workspace, function.end);
        const std::string name = workspace_function_name(workspace, *snapshot, function, start);
        if (!filter.empty() && lower_copy(name).find(filter) == std::string::npos) continue;
        const size_t match_index = total++;
        if (match_index < offset || functions.size() >= limit) continue;
        const auto* section = image->section_for_rva(start - image->image_base());
        json entry{{"address", hex_u64(start)}, {"name", name},
            {"size", end > start ? end - start : 0}, {"kind", function.thunk ? "thunk" : "function"},
            {"confidence", function.confidence}, {"provenance", static_cast<unsigned>(function.provenance)}};
        if (section) entry["section"] = section->name;
        functions.push_back(std::move(entry));
    }
    return tool_result_t::ok(json{{"total", total}, {"offset", offset},
        {"returned", functions.size()}, {"functions", std::move(functions)}});
}

static const char* workspace_xref_kind(aida::analysis::xref_kind_t kind)
{
    switch (kind) {
    case aida::analysis::xref_kind_t::call: return "call";
    case aida::analysis::xref_kind_t::read: return "read";
    case aida::analysis::xref_kind_t::write: return "write";
    case aida::analysis::xref_kind_t::address: return "data_ref";
    case aida::analysis::xref_kind_t::relocation: return "relocation";
    default: return "code";
    }
}

static tool_result_t workspace_xrefs_direction(const json& params, const workspace_ptr_t& workspace, bool to)
{
    uint64_t requested = 0;
    if (!parse_address_param(params, "address", requested)) return tool_result_t::error("'address' is required.");
    const uint64_t address = workspace_address(workspace, requested).value;
    auto snapshot = workspace->snapshot();
    auto image = workspace->image();
    if (!snapshot || !image) return workspace_error("Workspace analysis is not ready", "WORKSPACE_NOT_READY");
    json xrefs = json::array();
    size_t visited = 0;
    for (const auto& xref : snapshot->xrefs) {
        if ((visited++ & 0x3FFu) == 0 &&
            (workspace->cancellation_token().stop_requested() || mcp_standalone::current_call_cancelled()))
            return workspace_error("Cross-reference query was cancelled", "CANCELLED");
        const uint64_t source = workspace_va(workspace, xref.source);
        const uint64_t target = workspace_va(workspace, xref.target);
        if ((to ? target : source) != address) continue;
        xrefs.push_back(json{{"from_address", hex_u64(source)}, {"to_address", hex_u64(target)},
            {"type", workspace_xref_kind(xref.kind)}, {"disasm", ""},
            {"module", workspace->identity().bin_name()}, {"confidence", xref.confidence},
            {"provenance", static_cast<unsigned>(xref.provenance)}});
    }
    json result{{"address", hex_u64(address)}, {"count", xrefs.size()}, {"xrefs", std::move(xrefs)}};
    if (result["count"] == 0) result["note"] = "No workspace xrefs matched this address.";
    return tool_result_t::ok(result);
}

static tool_result_t workspace_get_xrefs(const json& params, const workspace_ptr_t& workspace)
{
    const std::string action = compat_action_name(params);
    const json payload = compat_action_payload(params);
    std::string direction = action.empty() ? payload.value("direction", std::string("to")) : action;
    direction = lower_copy(direction);
    if (direction == "to") return workspace_xrefs_direction(payload, workspace, true);
    if (direction == "from") return workspace_xrefs_direction(payload, workspace, false);
    if (direction != "both") return tool_result_t::error("get_xrefs unknown direction: " + direction);
    auto to_result = workspace_xrefs_direction(payload, workspace, true);
    auto from_result = workspace_xrefs_direction(payload, workspace, false);
    if (!to_result.success) return to_result;
    if (!from_result.success) return from_result;
    return tool_result_t::ok(json{{"address", payload["address"]}, {"direction", "both"},
        {"to", to_result.data}, {"from", from_result.data},
        {"count", to_result.data.value("count", 0) + from_result.data.value("count", 0)}});
}

static tool_result_t workspace_annotations(const json& params, const workspace_ptr_t& workspace)
{
    const std::string action = compat_action_name(params);
    const json payload = compat_action_payload(params);
    uint64_t requested = 0;
    if (!parse_address_param(payload, "address", requested)) return tool_result_t::error("'address' is required.");
    const uint64_t address = workspace_address(workspace, requested).value;
    if (action == "get_comment")
        return tool_result_t::ok(json{{"address", hex_u64(address)},
            {"comment", workspace_overlay_text(workspace,
                aida::analysis::overlay_operation_kind_t::comment, address)}});
    auto overlay = workspace->overlay();
    if (!overlay) return workspace_error("Workspace overlay is unavailable", "OVERLAY_UNAVAILABLE");
    aida::analysis::overlay_operation_t operation;
    operation.address = workspace_address(workspace, address);
    if (action == "set_comment") {
        operation.kind = aida::analysis::overlay_operation_kind_t::comment;
        operation.text = payload.value("comment", payload.value("text", std::string()));
    } else if (action == "rename_function") {
        operation.kind = aida::analysis::overlay_operation_kind_t::name;
        operation.name = payload.value("new_name", payload.value("name", std::string()));
    } else {
        return compat_unknown_action("disasm_annotations_manage", action);
    }
    aida::analysis::overlay_transaction_request_t request;
    request.operations.push_back(std::move(operation));
    auto committed = overlay->transact(request, workspace->cancellation_token());
    if (!committed) return workspace_failure(committed.error());
    return tool_result_t::ok(json{{"address", hex_u64(address)}, {"action", action},
        {"revision", committed.value().revision}, {"transaction_id", committed.value().transaction_id},
        {"committed", committed.value().committed}});
}

static tool_result_t workspace_section_info(const json&, const workspace_ptr_t& workspace)
{
    auto image = workspace->image();
    if (!image) return workspace_error("Workspace image metadata is unavailable", "WORKSPACE_NOT_READY");
    json sections = json::array();
    for (const auto& section : image->sections()) {
        const uint64_t va = image->image_base() + section.virtual_address;
        const uint64_t size = (std::max)(section.virtual_size, section.raw_size);
        sections.push_back(json{{"name", section.name}, {"va", hex_u64(va)}, {"size", size},
            {"end", hex_u64(va + size)}, {"readable", section.readable},
            {"writable", section.writable}, {"executable", section.executable}});
    }
    return tool_result_t::ok(json{{"image_base", hex_u64(image->image_base())},
        {"text_va", hex_u64(image->image_base() + image->entry_rva())},
        {"filename", workspace->identity().bin_name()}, {"section_count", sections.size()},
        {"sections", std::move(sections)}});
}

static tool_result_t workspace_search_bytes(const json& params, const workspace_ptr_t& workspace)
{
    if (workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot)
        return workspace_error("Bulk byte search is not supported for live snapshots",
                               "LIVE_TARGET_BULK_ANALYSIS_UNSUPPORTED");
    if (!params.contains("pattern") || !params["pattern"].is_string())
        return tool_result_t::error("'pattern' is required (hex string, supports '??' wildcards).");
    std::vector<uint8_t> needle;
    std::vector<bool> wildcards;
    if (!parse_hex_pattern(params["pattern"].get<std::string>(), needle, wildcards))
        return tool_result_t::error("Invalid hex pattern.");
    if (needle.size() > 4096)
        return workspace_error("Hex pattern exceeds the 4096-byte safety limit", "LIMIT_EXCEEDED");
    size_t max_hits = 256;
    if (params.contains("max_hits") && params["max_hits"].is_number_unsigned())
        max_hits = (std::min<size_t>)(4096, (std::max<size_t>)(1, params["max_hits"].get<size_t>()));
    auto image = workspace->image();
    if (!image) return workspace_error("Workspace image metadata is unavailable", "WORKSPACE_NOT_READY");
    constexpr uint64_t window_size = 4ULL * 1024ULL * 1024ULL;
    json matches = json::array();
    size_t total = 0;
    for (const auto& section : image->sections()) {
        if (!section.executable || section.raw_size < needle.size()) continue;
        uint64_t position = 0;
        while (position < section.raw_size) {
            if (workspace->cancellation_token().stop_requested() || mcp_standalone::current_call_cancelled())
                return workspace_error("Byte search was cancelled", "CANCELLED");
            const uint64_t overlap = position == 0 ? 0 : needle.size() - 1;
            const uint64_t begin = position - overlap;
            const uint64_t remaining = section.raw_size - begin;
            const uint64_t read_size = (std::min)(remaining, window_size + overlap);
            auto bytes = workspace->provider().read_vector(
                static_cast<uint64_t>(section.raw_offset) + begin, read_size,
                window_size + needle.size(), workspace->cancellation_token());
            if (!bytes) return workspace_failure(bytes.error());
            for (size_t index = 0; index + needle.size() <= bytes.value().size(); ++index) {
                if ((index & 0xFFFu) == 0 &&
                    (workspace->cancellation_token().stop_requested() || mcp_standalone::current_call_cancelled()))
                    return workspace_error("Byte search was cancelled", "CANCELLED");
                const uint64_t section_offset = begin + index;
                if (section_offset < position) continue;
                bool equal = true;
                for (size_t byte_index = 0; byte_index < needle.size(); ++byte_index) {
                    if (!wildcards[byte_index] && bytes.value()[index + byte_index] != needle[byte_index]) {
                        equal = false;
                        break;
                    }
                }
                if (!equal) continue;
                ++total;
                if (matches.size() < max_hits)
                    matches.push_back(json{{"address", hex_u64(image->image_base() +
                        section.virtual_address + section_offset)}});
            }
            position += (std::min)(window_size, static_cast<uint64_t>(section.raw_size) - position);
        }
    }
    return tool_result_t::ok(json{{"pattern", params["pattern"]}, {"total_hits", total},
        {"returned", matches.size()}, {"matches", std::move(matches)}, {"truncated", total > max_hits}});
}

static tool_result_t workspace_strings(const json& params, const workspace_ptr_t& workspace)
{
    if (workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot)
        return workspace_error("Bulk string enumeration is not supported for live snapshots",
                               "LIVE_TARGET_BULK_ANALYSIS_UNSUPPORTED");
    auto snapshot = workspace->snapshot();
    auto image = workspace->image();
    if (!snapshot || !image) return workspace_error("Workspace analysis is not ready", "WORKSPACE_NOT_READY");
    size_t min_length = 4;
    if (params.contains("min_length") && params["min_length"].is_number_unsigned())
        min_length = (std::min<size_t>)(128, (std::max<size_t>)(2, params["min_length"].get<size_t>()));
    size_t limit = 2048;
    if (params.contains("limit") && params["limit"].is_number_unsigned())
        limit = (std::min<size_t>)(8192, (std::max<size_t>)(1, params["limit"].get<size_t>()));
    const std::string encoding = lower_copy(params.value("encoding", std::string("ascii")));
    if (encoding != "ascii" && encoding != "utf16" && encoding != "both")
        return tool_result_t::error("encoding must be one of: ascii, utf16, both");
    json strings = json::array();
    size_t total = 0;
    size_t visited = 0;
    for (const auto& value : snapshot->strings) {
        if ((visited++ & 0x3FFu) == 0 &&
            (workspace->cancellation_token().stop_requested() || mcp_standalone::current_call_cancelled()))
            return workspace_error("String enumeration was cancelled", "CANCELLED");
        const bool utf16 = value.encoding == aida::analysis::string_encoding_t::utf16_le;
        if (value.value.size() < min_length || (encoding == "ascii" && utf16) ||
            (encoding == "utf16" && !utf16)) continue;
        ++total;
        if (strings.size() >= limit) continue;
        strings.push_back(json{{"address", hex_u64(workspace_va(workspace, value.address))},
            {"encoding", utf16 ? "utf16" : "ascii"}, {"length", value.value.size()},
            {"text", value.value}, {"confidence", value.confidence},
            {"provenance", static_cast<unsigned>(value.provenance)}});
    }
    return tool_result_t::ok(json{{"total_found", total}, {"returned", strings.size()},
        {"limit", limit}, {"truncated", strings.size() < total}, {"scan_truncated", false},
        {"sections_total", image->sections().size()}, {"sections_scanned", image->sections().size()},
        {"sections_skipped", 0}, {"bytes_scanned", workspace->provider().size()},
        {"per_section_byte_cap", 0}, {"min_length", min_length}, {"encoding", encoding},
        {"strings", std::move(strings)}});
}

void register_disasm_tools(mcp_standalone::server_t& srv)
{

    srv.register_tool({
        "disasm_get_instruction",
        "Return the decoded instruction at an address: mnemonic, operands, length, raw bytes, comment, and branch/call/ret flags.",
        {{"address", "string", "Instruction address (hex string or integer)", true}},
        true, {}}, workspace_get_instruction);

    srv.register_tool({
        "disasm_get_function_bounds",
        "Return the bounding function metadata (start, end, size, display name, section) for the function that contains a given address.",
        {{"address", "string", "Any address inside the function (hex string or integer)", true}},
        true, {}}, workspace_get_function_bounds);

    srv.register_tool({
        "disasm_get_function_disassembly",
        "Return the decoded instruction list of the function containing the address, up to max_instrs (default 256, max 8192).",
        {{"address", "string", "Any address inside the function (hex string or integer)", true},
         {"max_instrs", "number", "Maximum instructions to return (default 256, max 8192)", false}},
        true, {}}, workspace_get_function_disassembly);

    srv.register_tool({
        "disasm_list_functions",
        "List functions known to the analysis function index. Supports case-insensitive substring filter on the display name and offset/limit paging.",
        {{"filter", "string", "Optional case-insensitive substring filter applied to the function name", false},
         {"offset", "number", "Number of matches to skip (default 0)", false},
         {"limit",  "number", "Maximum matches to return (default 200, max 5000)", false}},
        true, {}}, workspace_list_functions);

    srv.register_tool({
        "get_xrefs",
        "Return cached cross-references for an address from the xref_db. Set direction to to, from, or both.",
        {{"address", "string", "Address (hex string or integer)", true},
         {"direction", "string", "to|from|both; action is accepted as an alias", false},
         {"action", "string", "Optional alias for direction", false},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false}},
        true, {}}, workspace_get_xrefs);

    srv.register_tool({
        "disasm_annotations_manage",
        "Manage disassembly annotations. Actions: get_comment, set_comment, rename_function.",
        {{"action", "string", "get_comment|set_comment|rename_function", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
         {"address", "string", "Instruction or function address (hex string or integer)", false},
         {"comment", "string", "Comment text; empty clears the comment", false},
         {"new_name", "string", "Function display name; empty clears the rename", false},
         {"name", "string", "Alias for new_name", false}},
        false, {}}, workspace_annotations);

    srv.register_tool({
        "disasm_get_section_info",
        "Return the executable section table of the currently loaded disassembly file (va, size, image_base, text_va).",
        {},
        true, {}}, workspace_section_info);

    srv.register_tool({
        "disasm_search_bytes",
        "Scan executable sections of the loaded file for a hex byte pattern. Pattern accepts hex bytes separated by spaces or commas; '??' is a single-byte wildcard.",
        {{"pattern", "string", "Hex pattern (e.g. '48 8B 05 ?? ?? ?? ??')", true},
         {"max_hits","number", "Maximum match addresses to return (default 256, max 4096)", false}},
        true, {}}, workspace_search_bytes);

    srv.register_tool({
        "disasm_get_strings",
        "Extract printable string literals from the loaded disassembly file. Streams ASCII and/or UTF-16LE runs from the data sections.",
        {{"min_length", "number", "Minimum run length in characters (default 4)", false},
         {"encoding",   "string", "ascii, utf16, or both (default ascii)", false},
         {"limit",      "number", "Maximum strings to return (default 2048, max 8192)", false}},
        true, {}}, workspace_strings);





}

}
