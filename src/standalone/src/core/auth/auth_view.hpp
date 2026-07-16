#pragma once

#include <string>

namespace aida {
namespace auth_view {

	void initialize();
	void shutdown();
	void render(float panel_w, float panel_h);
	bool any_login_in_progress();
	std::string last_error();

	void focus_provider(const std::string& provider_id);
	bool is_provider_authenticated(const std::string& provider_id);

}
}
