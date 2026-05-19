#pragma once

#include <string>

namespace aida {
namespace burp {
namespace camoufox {
namespace install {

enum class install_state_t : int
{
    unknown         = 0,
    checking        = 1,
    available       = 2,
    missing_python  = 3,
    missing_module  = 4,
    missing_browser = 5,
    installing      = 6,
    install_failed  = 7,
    ok              = 8
};

struct status_t
{
    install_state_t state = install_state_t::unknown;
    std::string     python_path;
    std::string     module_version;
    std::string     browser_path;
    std::string     last_message;
};

bool      initialize();
void      shutdown();
status_t  probe();
bool      pip_install_module(std::string& out_log);
bool      fetch_browser(std::string& out_log);
bool      pip_install_async();
bool      fetch_browser_async();
status_t  get_status();
std::string last_error();

}
}
}
}
