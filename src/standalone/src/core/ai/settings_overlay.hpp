#pragma once

#include <string>

#include "standalone_chat.hpp"


namespace aida {
namespace settings_overlay {


	enum tab_index_t : int
	{
		tab_accounts          = 0,
		tab_agents            = 1,
		tab_skills            = 2,
		tab_mcp_servers       = 3,
		tab_editor_theme      = 4,
		tab_count             = 5
	};


	void initialize();
	void shutdown();
	void render_inline(float panel_w, float panel_h);

	void open();
	void close();
	void toggle();
	bool is_open();

	void set_active_tab(tab_index_t tab_index);
	tab_index_t active_tab();

	void open_to_provider(const std::string& provider_id);
	std::string consume_pending_provider_focus();


}
}
