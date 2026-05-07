#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <ida.hpp>
#include <hexrays.hpp>

#include "../agent_tools.hpp"
#include "vuln_common.hpp"

namespace agent_tools
{
namespace vuln_tools
{

void register_tools();
void register_advanced_tools();

}
}

namespace aida
{
namespace vuln
{

namespace callsites
{
    std::vector<callsite_t> all_calls_to(const std::vector<std::string>& target_names);
    std::vector<callsite_t> input_source_callsites();
    bool is_call_arg_literal(const cfunc_t& cf, ea_t call_ea, int arg_idx);

    namespace tools
    {
        void register_tier1_callsite_tools();
    }
}

namespace strings_engine
{
    std::vector<vuln_finding_t> find_hardcoded_credentials(int max_findings = 256);
    std::vector<vuln_finding_t> find_weak_crypto(int max_findings = 256);

    namespace tools
    {
        void register_tier1_string_tools();
    }
}

namespace microcode
{
    void register_tier1_microcode_tools();
}

namespace cfg_engine
{
    struct indirect_target_t
    {
        ea_t        target_ea = BADADDR;
        std::string source;
        std::string name;
        std::string rationale;
    };

    struct indirect_call_t
    {
        ea_t                              call_ea = BADADDR;
        ea_t                              func_ea = BADADDR;
        std::vector<indirect_target_t>    targets;
        std::string                       reason;
    };

    struct bypass_path_t
    {
        ea_t                         func_ea = BADADDR;
        ea_t                         check_ea = BADADDR;
        ea_t                         sink_ea = BADADDR;
        std::vector<ea_t>            block_path;
        std::vector<ea_t>            ea_trace;
        std::string                  rationale;
    };

    std::vector<indirect_call_t> find_indirect_calls(ea_t func_ea);
    std::vector<bypass_path_t>   find_bypass_paths(ea_t check_ea, ea_t sink_ea);
    bool block_post_dominates(ea_t func_ea, int from_block, int to_block);

    void register_tier1_cfg_tools();
}

namespace taint
{
    namespace tools
    {
        void register_tier1_taint_tools();
        void register_tier2_taint_tools();
    }
}

namespace kernel_engine
{
    struct ioctl_handler_t
    {
        ea_t                       handler_ea = BADADDR;
        std::string                handler_name;
        std::vector<uint32_t>      ioctl_codes;
    };

    struct ioctl_decoded_t
    {
        uint32_t     code = 0;
        uint16_t     device_type = 0;
        uint16_t     function_code = 0;
        uint8_t      method = 0;
        uint8_t      access = 0;
        const char*  method_name = "";
        const char*  access_name = "";
    };

    bool is_kernel_driver();
    std::vector<ioctl_handler_t> find_ioctl_handlers();
    std::vector<vuln_finding_t>  find_user_pointer_derefs(int max_findings = 64);
    ioctl_decoded_t              decode_ioctl(uint32_t code);

    namespace tools
    {
        void register_tier1_kernel_tools();
    }
}

namespace surface_engine
{
    struct attack_surface_score_t
    {
        ea_t        func_ea = BADADDR;
        int         total_score = 0;
        int         input_proximity = 0;
        int         sink_count = 0;
        int         missing_validators = 0;
        int         complexity = 0;
        int         taint_paths = 0;
        std::string classification;
    };

    attack_surface_score_t score_function(ea_t func_ea);
    std::vector<ea_t>      attacker_reachable_functions();
    std::string            classify_function_role(ea_t func_ea);
    std::vector<vuln_finding_t> enumerate_callbacks();
    std::vector<vuln_finding_t> find_writable_executable_pages();

    namespace tools
    {
        void register_tier2_surface_tools();
    }
}

}
}
