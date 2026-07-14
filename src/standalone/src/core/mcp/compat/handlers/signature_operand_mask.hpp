#pragma once

#include "signatures.h"

namespace aida::standalone::mcp::compat::handlers {

struct signature_operand_mask_result_t final {
    bool success = false;
    std::vector<std::uint8_t> stable_mask;
    std::size_t dynamic_byte_count = 0;
    std::size_t relocation_byte_count = 0;
    std::string error;
};

signature_operand_mask_result_t build_signature_operand_mask(
    const signature_instruction_t& instruction);

}
