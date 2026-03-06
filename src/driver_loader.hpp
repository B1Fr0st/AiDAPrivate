#pragma once


#ifdef __NT__

namespace driver_loader {


bool initialize_and_load();


bool is_driver_loaded();

}

#endif
