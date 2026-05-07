#pragma once

#include "standalone_chat.hpp"


namespace aida {
namespace settings_overlay {


	enum tab_index_t : int
	{
		tab_accounts          = 0,
		tab_providers         = 1,
		tab_agents            = 2,
		tab_skills            = 3,
		tab_mcp_servers       = 4,
		tab_permissions       = 5,
		tab_compaction_cost   = 6,
		tab_editor_theme      = 7,
		tab_ida_pro           = 8,
		tab_count             = 9
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


}
}
