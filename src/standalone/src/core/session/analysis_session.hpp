#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "../disasm/disasm_view.hpp"
#include "../disasm/decompiler_engine.hpp"
#include "../disasm/function_index.hpp"
#include "../disasm/xref_index.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "../analysis/symbol_store.hpp"
#include "../analysis/types_hub_view.hpp"
#include "../analysis/xref_db.hpp"
#include "../scanner/crypto_scanner.hpp"
#include "../debugger/debugger_engine.hpp"

namespace analysis_session {

struct live_attach_snapshot_t {
	std::vector<debugger_engine::breakpoint_t> breakpoints;
	std::vector<debugger_engine::watch_entry_t> watches;
};

struct analysis_session_t {
	std::string id;
	std::string path;
	std::string filename;
	uint64_t    last_active_steady_ms = 0;

	uint32_t      attached_pid = 0;
	std::wstring  process_name;

	std::unique_ptr<DisasmFile>                                disasm_file;
	std::unique_ptr<function_index::detail::cache_t>           fn_cache;
	std::unique_ptr<xref_index::detail::registry_t>            xref_registry;
	std::unique_ptr<symbol_store::snapshot_t>                  symbol_snap;
	std::unique_ptr<decompiler_engine::snapshot_t>             decomp_snap;
	std::unique_ptr<disasm_view::snapshot_t>                   disasm_view_snap;
	std::unique_ptr<types_hub_view::snapshot_t>                types_hub_snap;
	std::unique_ptr<crypto_scanner::snapshot_t>                crypto_snap;
	std::unique_ptr<xref_db::snapshot_t>                       xref_db_snap;
	std::unique_ptr<live_attach_snapshot_t>                    live_snap;
};

static constexpr size_t kMaxSessions = 16;

enum class session_kind_t : int {
	static_file = 0,
	live_attach = 1,
};

struct session_summary_t {
	std::string   id;
	session_kind_t kind = session_kind_t::static_file;
	std::string   path;
	std::string   filename;
	uint32_t      pid = 0;
	std::string   process_name;
	bool          is_active = false;
	bool          is_alive = true;
	uint64_t      last_active_steady_ms = 0;
};

bool        open_session(const std::string& path);
bool        open_attach_session(uint32_t pid, std::string* out_err);
bool        switch_session(size_t idx);
bool        close_session(size_t idx);
size_t      active_session_idx();
size_t      session_count();
const analysis_session_t* session_at(size_t idx);
bool        find_session_by_path(const std::string& path, size_t* out_idx);
bool        find_session_by_pid(uint32_t pid, size_t* out_idx);
bool        find_session_by_id(const std::string& session_id, size_t* out_idx);
void        prune_lru(size_t max_keep);
const char* last_error();

bool                          has_active_target();
std::vector<session_summary_t> list_session_summaries();
session_summary_t              summarize_session_at(size_t idx);

}
