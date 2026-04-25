#pragma once

#include <string>

namespace aida {
namespace provider_view {

	void initialize();
	void shutdown();
	void render(float panel_w, float panel_h);
	void render_chat_header_picker(float max_width);
	const std::string& last_error();

}
}
