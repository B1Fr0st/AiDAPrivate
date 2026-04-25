#pragma once

#include <string>

namespace aida {
namespace auth_view {

	void initialize();
	void shutdown();
	void render(float panel_w, float panel_h);
	bool any_login_in_progress();
	const std::string& last_error();

}
}
