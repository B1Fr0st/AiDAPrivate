#pragma once

#include "arch_decoder.hpp"

namespace aida::analysis {

workspace_result_t<void> register_arm_decoder_backends(
    arch_decoder_registry_t& registry);

}
