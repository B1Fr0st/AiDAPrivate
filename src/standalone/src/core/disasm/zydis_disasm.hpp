
#pragma once
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
#else
#include <windows.h>
#include "../../helpers/win32_dialog.hpp"
#endif
#include <Zydis/Zydis.h>

#include <vector>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <thread>
#include <algorithm>
#include <memory>
#include <utility>

#include "../analysis/workspace/analysis_workspace.hpp"
#include "../analysis/workspace/x86_decoder.hpp"


struct mem_op_snapshot_t
{
    uint16_t base_reg     = 0;
    uint16_t index_reg    = 0;
    uint8_t  scale        = 0;
    int64_t  disp         = 0;
    uint16_t size         = 0;
    uint8_t  segment      = 0;
    bool     has_disp     = false;
};

struct AsmInstr
{
    uint64_t addr           = 0;
    uint8_t  raw[16]        = {};
    int      len            = 1;
    char     mnem[32]       = {};
    char     ops[128]       = {};
    bool     is_branch      = false;
    bool     is_call        = false;
    bool     is_ret         = false;
    bool     is_nop         = false;
    bool     is_priv        = false;
    uint64_t branch_target  = 0;
    int64_t  imm_signed     = 0;
    uint64_t imm_unsigned   = 0;
    bool     has_imm        = false;
    uint8_t  imm_op_index   = 0xFF;
    bool     has_mem_op     = false;
    mem_op_snapshot_t mem_op{};
};


struct PESection
{
    uint64_t             va = 0;
    std::vector<uint8_t> bytes;
    bool                 is_executable = true;
};


struct DisasmFile
{
    std::string            path;
    std::string            filename;
    uint64_t               image_base = 0;
    uint64_t               entry_point = 0;
    uint64_t               text_va    = 0;
    uint16_t               machine = IMAGE_FILE_MACHINE_AMD64;
    bool                   is_64bit = true;
	std::vector<PESection> sections;
	bool                   loaded = false;
	std::string            err;
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
};


struct DisasmState
{
    DisasmFile file;
    int  ctx_row   = -1;
    bool show_ctx  = false;


    bool     live_mode       = false;
    uint32_t live_pid        = 0;
    uint64_t live_base       = 0;
    uint64_t live_size       = 0;
    uint64_t live_floor_va   = 0;
    uint64_t live_view_addr  = 0;
    uint64_t live_window     = 0x4000;
    std::string live_module;
    float    live_refresh_timer = 0.f;
    float    live_refresh_interval = 2.0f;
    bool     live_paused     = false;
    bool     live_needs_refresh = false;
    std::atomic<bool> live_decoding{false};
    std::atomic<bool> live_decode_failed{false};
    std::atomic<int>  live_fail_count{0};
    std::vector<AsmInstr> live_pending_instrs;
    uint64_t live_pending_va = 0;
    std::atomic<bool> live_pending_ready{false};
	uint64_t goto_address = 0;
	bool has_new_goto = false;
	bool last_swap_was_live = false;
};

namespace static_analysis
{
    inline bool read_bytes_from_pe(const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
                                   const aida::analysis::address_t& address,
                                   size_t len,
                                   std::vector<uint8_t>& out)
    {
        out.clear();
        if (!workspace || workspace->target_kind() !=
                aida::analysis::target_kind_t::static_file ||
            len == 0 || len > (64ull << 20)) return false;
        if (address.architecture != aida::analysis::architecture_id_t::unknown &&
            address.architecture != workspace->identity().architecture())
            return false;
        const auto image = workspace->image();
        if (!image) return false;
        uint64_t rva = 0;
        uint64_t provider_offset = 0;
        if (address.space == aida::analysis::address_space_id_t::relative_virtual) {
            rva = address.value;
        } else if (address.space == aida::analysis::address_space_id_t::virtual_address) {
            auto mapped = image->va_to_rva(address.value);
            if (!mapped) return false;
            rva = mapped.value();
        } else if (address.space == aida::analysis::address_space_id_t::file_offset) {
            provider_offset = address.value;
        } else {
            return false;
        }
        if (address.space != aida::analysis::address_space_id_t::file_offset) {
            auto file_offset = image->rva_to_file_offset(rva, len);
            if (!file_offset) return false;
            provider_offset = file_offset.value();
        }
        out.resize(len);
        auto read = workspace->provider().read_exact(provider_offset, out.data(), len,
                                                     workspace->cancellation_token());
        if (!read) {
            out.clear();
            return false;
        }
        return true;
    }

    inline bool read_bytes_from_pe(const DisasmFile& file, uint64_t va, size_t len, std::vector<uint8_t>& out)
    {
        if (file.workspace) {
            const auto image = file.workspace->image();
            if (!image) return false;
            aida::analysis::address_t address;
            address.space = aida::analysis::address_space_id_t::virtual_address;
            address.value = va;
            address.architecture = image->architecture();
            address.mode = image->architecture_mode();
            return read_bytes_from_pe(file.workspace, address, len, out);
        }
        out.clear();
        if (!file.loaded || file.sections.empty() || len == 0) return false;

        for (auto& sec : file.sections) {
            uint64_t sec_start = sec.va;
            uint64_t sec_end   = sec_start + sec.bytes.size();
            if (va < sec_start || va >= sec_end) continue;

            size_t src_off = static_cast<size_t>(va - sec_start);
            size_t copy_sz = sec.bytes.size() - src_off;
            if (copy_sz > len) copy_sz = len;
            if (copy_sz == 0) return false;
            out.assign(sec.bytes.data() + src_off, sec.bytes.data() + src_off + copy_sz);
            return true;
        }
        return false;
    }

    inline uint64_t total_image_size(const DisasmFile& file)
    {
        if (file.workspace) {
            const auto image = file.workspace->image();
            return image ? image->image_size() : 0;
        }
        uint64_t max_end = 0;
        for (auto& sec : file.sections) {
            uint64_t end = sec.va + sec.bytes.size();
            if (end > max_end) max_end = end;
        }
        if (max_end <= file.image_base) return 0;
        return max_end - file.image_base;
    }
}

namespace zydis_detail
{
    struct contexts_t {
        ZydisDecoder decoder64{};
        ZydisDecoder decoder32{};
        ZydisFormatter formatter{};
        bool ready = false;
    };

    inline contexts_t& contexts()
    {
        thread_local contexts_t value;
        if (!value.ready) {
            const ZyanStatus decoder64_status = ZydisDecoderInit(
                &value.decoder64, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
            const ZyanStatus decoder32_status = ZydisDecoderInit(
                &value.decoder32, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
            const ZyanStatus formatter_status = ZydisFormatterInit(
                &value.formatter, ZYDIS_FORMATTER_STYLE_INTEL);
            const ZyanStatus segment_status = ZydisFormatterSetProperty(
                &value.formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_FALSE);
            const ZyanStatus size_status = ZydisFormatterSetProperty(
                &value.formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_FALSE);
            value.ready = ZYAN_SUCCESS(decoder64_status) && ZYAN_SUCCESS(decoder32_status) &&
                          ZYAN_SUCCESS(formatter_status) && ZYAN_SUCCESS(segment_status) &&
                          ZYAN_SUCCESS(size_status);
        }
        return value;
    }

    inline void ensure_init()
    {
        (void)contexts();
    }

    inline ZydisDecoder& decoder()
    {
        return contexts().decoder64;
    }

    inline ZydisFormatter& formatter()
    {
        return contexts().formatter;
    }
}


inline AsmInstr zydis_decode_one(const uint8_t* code, int avail, uint64_t va, bool is_64bit = true)
{
    auto& contexts = zydis_detail::contexts();

    AsmInstr ins;
    ins.addr = va;

    if (!contexts.ready || !code || avail <= 0) {
        snprintf(ins.mnem, sizeof(ins.mnem), "db");
        snprintf(ins.ops, sizeof(ins.ops), "??");
        return ins;
    }

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
            is_64bit ? &contexts.decoder64 : &contexts.decoder32,
            code,
            static_cast<ZyanUSize>(avail),
            &instruction,
            operands)))
    {
        ins.len = 1;
        snprintf(ins.mnem, sizeof(ins.mnem), "db");
        snprintf(ins.ops, sizeof(ins.ops), "0x%02X", code[0]);
        ins.raw[0] = code[0];
        return ins;
    }

    ins.len = static_cast<int>(instruction.length);
    const int copy_len = (ins.len < 16) ? ins.len : 16;
    memcpy(ins.raw, code, static_cast<size_t>(copy_len));


    char full[256] = {};
    ZydisFormatterFormatInstruction(
        &contexts.formatter, &instruction, operands,
        instruction.operand_count_visible,
        full, sizeof(full), va, ZYAN_NULL);

    const char* mnemonic_str = ZydisMnemonicGetString(instruction.mnemonic);
    if (mnemonic_str)
        snprintf(ins.mnem, sizeof(ins.mnem), "%s", mnemonic_str);


    const char* space = strchr(full, ' ');
    if (space)
        snprintf(ins.ops, sizeof(ins.ops), "%s", space + 1);


    switch (instruction.meta.category) {
    case ZYDIS_CATEGORY_CALL:      ins.is_call   = true; break;
    case ZYDIS_CATEGORY_RET:       ins.is_ret    = true; break;
    case ZYDIS_CATEGORY_COND_BR:
    case ZYDIS_CATEGORY_UNCOND_BR: ins.is_branch = true; break;
    case ZYDIS_CATEGORY_NOP:       ins.is_nop    = true; break;
    default: break;
    }

    if (instruction.meta.category == ZYDIS_CATEGORY_SYSTEM ||
        instruction.meta.category == ZYDIS_CATEGORY_INTERRUPT)
        ins.is_priv = true;

    if (ins.is_branch || ins.is_call) {
        for (uint8_t oi = 0; oi < instruction.operand_count_visible; ++oi) {
            const auto& op = operands[oi];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                uint64_t abs_addr = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &op, va, &abs_addr))) {
                    ins.branch_target = abs_addr;
                    break;
                }
            }
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !op.imm.is_relative) {
                ins.branch_target = static_cast<uint64_t>(op.imm.value.u);
                break;
            }
        }
    }

    for (uint8_t oi = 0; oi < instruction.operand_count_visible; ++oi) {
        const auto& op = operands[oi];
        if (!ins.has_imm && op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !op.imm.is_relative) {
            ins.has_imm = true;
            ins.imm_op_index = oi;
            ins.imm_unsigned = static_cast<uint64_t>(op.imm.value.u);
            ins.imm_signed = static_cast<int64_t>(op.imm.value.s);
        }
        if (!ins.has_mem_op && op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            ins.has_mem_op = true;
            ins.mem_op.base_reg = static_cast<uint16_t>(op.mem.base);
            ins.mem_op.index_reg = static_cast<uint16_t>(op.mem.index);
            ins.mem_op.scale = static_cast<uint8_t>(op.mem.scale);
            ins.mem_op.disp = static_cast<int64_t>(op.mem.disp.value);
            ins.mem_op.size = static_cast<uint16_t>(op.size);
            ins.mem_op.segment = static_cast<uint8_t>(op.mem.segment);
            ins.mem_op.has_disp = op.mem.disp.has_displacement != ZYAN_FALSE;
        }
        if (ins.has_imm && ins.has_mem_op)
            break;
    }

    return ins;
}


namespace disasm
{
    inline bool bind_workspace(const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
                               DisasmFile& out)
    {
        out = {};
        if (!workspace) {
            out.err = "Workspace is unavailable";
            return false;
        }
        const auto image = workspace->image();
        if (!image) {
            out.err = "Workspace image is unavailable";
            return false;
        }
        out.workspace = workspace;
        out.path = workspace->identity().normalized_source_path();
        out.filename = workspace->identity().bin_name();
        out.image_base = image->image_base();
        if (image->entry_rva() != 0) {
            auto entry = image->rva_to_va(image->entry_rva());
            if (!entry) {
                out.err = entry.error().stable_code() + ": " + entry.error().message;
                return false;
            }
            out.entry_point = entry.value();
        }
        out.machine = image->machine();
        out.is_64bit = image->architecture() == aida::analysis::architecture_id_t::x86_64;
        out.text_va = out.entry_point;
        for (const auto& section : image->sections()) {
            if (section.executable) {
                auto section_address = image->rva_to_va(section.virtual_address);
                if (!section_address) {
                    out.err = section_address.error().stable_code() + ": " +
                        section_address.error().message;
                    return false;
                }
                out.text_va = section_address.value();
                break;
            }
        }
        out.loaded = true;
        return true;
    }

    inline aida::analysis::workspace_result_t<std::vector<AsmInstr>> format_page(
        const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
        size_t offset,
        size_t count,
        const aida::analysis::cancellation_token_t& cancel = {})
    {
        using namespace aida::analysis;
        if (!workspace || count > 50000) {
            return workspace_result_t<std::vector<AsmInstr>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                                     "Workspace and bounded instruction count are required",
                                     "disasm.format_page"));
        }
        const auto publication = workspace->analysis_publication();
        const auto image = workspace->image();
        if (!publication || !publication->snapshot || !image ||
            offset > publication->snapshot->instructions.size()) {
            return workspace_result_t<std::vector<AsmInstr>>::failure(
                make_workspace_error(workspace_error_code_t::out_of_range,
                                     "Instruction page is outside the current publication",
                                     "disasm.format_page"));
        }
        if (publication->binary_id != workspace->identity().binary_id() ||
            publication->generation != workspace->generation()) {
            return workspace_result_t<std::vector<AsmInstr>>::failure(
                make_workspace_error(workspace_error_code_t::stale_generation,
                                     "Instruction publication does not match the workspace generation",
                                     "disasm.format_page"));
        }
        auto decoder = worker_owned_x86_decoder_t::create(image->architecture_mode());
        if (!decoder)
            return workspace_result_t<std::vector<AsmInstr>>::failure(decoder.error());
        const size_t remaining = publication->snapshot->instructions.size() - offset;
        const size_t end = offset + (std::min)(remaining, count);
        std::vector<AsmInstr> result;
        result.reserve(end - offset);
        for (size_t index = offset; index < end; ++index) {
            if (cancel.stop_requested()) {
                auto error = make_workspace_error(cancel.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                    "Instruction formatting was cancelled", "disasm.format_page");
                error.cancellation = true;
                error.deadline = cancel.deadline_exceeded();
                return workspace_result_t<std::vector<AsmInstr>>::failure(std::move(error));
            }
            const auto& record = publication->snapshot->instructions[index];
            auto text = decoder.value()->format_one(workspace->provider(), *image, record, {}, cancel);
            if (!text)
                return workspace_result_t<std::vector<AsmInstr>>::failure(text.error());
            AsmInstr formatted;
            if (record.address.space == address_space_id_t::relative_virtual) {
                auto address = image->rva_to_va(record.address.value);
                if (!address)
                    return workspace_result_t<std::vector<AsmInstr>>::failure(address.error());
                formatted.addr = address.value();
            } else {
                formatted.addr = record.address.value;
            }
            formatted.len = record.length;
            const auto separator = text.value().find(' ');
            const auto mnemonic = text.value().substr(0, separator);
            const auto operands = separator == std::string::npos
                ? std::string{}
                : text.value().substr(separator + 1);
            std::snprintf(formatted.mnem, sizeof(formatted.mnem), "%s", mnemonic.c_str());
            std::snprintf(formatted.ops, sizeof(formatted.ops), "%s", operands.c_str());
            formatted.is_call = (record.flow_flags & flow_call) != 0;
            formatted.is_branch = (record.flow_flags & flow_branch) != 0;
            formatted.is_ret = (record.flow_flags & flow_return) != 0;
            formatted.is_priv = (record.flow_flags & flow_privileged) != 0;
            for (uint16_t target_index = 0; target_index < record.target_fact_count; ++target_index) {
                const size_t fact_index = static_cast<size_t>(record.target_fact_begin) + target_index;
                if (fact_index >= publication->snapshot->target_facts.size()) break;
                const auto& target = publication->snapshot->target_facts[fact_index];
                if (target.kind == target_kind_record_t::branch ||
                    target.kind == target_kind_record_t::call) {
                    if (target.target.space == address_space_id_t::relative_virtual) {
                        auto target_address = image->rva_to_va(target.target.value);
                        if (!target_address)
                            return workspace_result_t<std::vector<AsmInstr>>::failure(
                                target_address.error());
                        formatted.branch_target = target_address.value();
                    } else {
                        formatted.branch_target = target.target.value;
                    }
                    break;
                }
            }
            result.push_back(formatted);
        }
        return workspace_result_t<std::vector<AsmInstr>>::success(std::move(result));
    }


    inline bool summarize_bytes(const uint8_t* data, size_t size, size_t& zero_count, size_t& longest_zero_run)
    {
        zero_count = 0;
        longest_zero_run = 0;
        if (!data || size == 0) return false;
        size_t current = 0;
        for (size_t i = 0; i < size; ++i) {
            if (data[i] == 0) {
                ++zero_count;
                ++current;
                if (current > longest_zero_run)
                    longest_zero_run = current;
            } else {
                current = 0;
            }
        }
        return true;
    }

    inline bool buffer_is_zero_padding(const std::vector<uint8_t>& bytes)
    {
        size_t zero_count = 0;
        size_t longest_zero_run = 0;
        if (!summarize_bytes(bytes.data(), bytes.size(), zero_count, longest_zero_run))
            return true;
        return longest_zero_run >= 256 || (bytes.size() >= 256 && zero_count * 100 >= bytes.size() * 90);
    }

    inline std::string open_file_dialog(HWND owner)
    {
        char buf[MAX_PATH] = {};
        static const char k_filter[] =
            "PE Files (*.exe;*.dll;*.sys;*.bin)\0*.exe;*.dll;*.sys;*.bin\0"
            "All files (*.*)\0*.*\0\0";
        if (win32_dialog::show_open_file_dialog(owner,
                "Open PE File",
                k_filter,
                buf, sizeof(buf),
                "disasm::open_file_dialog"))
            return std::string(buf);
        return {};
    }
















}
