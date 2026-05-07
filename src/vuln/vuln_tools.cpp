#include "../aida_pro.hpp"
#include "vuln_tools.hpp"

namespace agent_tools
{
namespace vuln_tools
{

void register_tools()
{
    aida::vuln::callsites::tools::register_tier1_callsite_tools();
    aida::vuln::strings_engine::tools::register_tier1_string_tools();
    aida::vuln::microcode::register_tier1_microcode_tools();
    aida::vuln::cfg_engine::register_tier1_cfg_tools();
    aida::vuln::kernel_engine::tools::register_tier1_kernel_tools();
    aida::vuln::taint::tools::register_tier1_taint_tools();
}

void register_advanced_tools()
{
    aida::vuln::taint::tools::register_tier2_taint_tools();
    aida::vuln::surface_engine::tools::register_tier2_surface_tools();
}

}
}
