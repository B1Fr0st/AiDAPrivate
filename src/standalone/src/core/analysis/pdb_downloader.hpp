#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>

namespace pdb_downloader {

struct progress_t {
	uint64_t bytes_received = 0;
	uint64_t bytes_total = 0;
	int      percent = 0;
};

using progress_callback_t = std::function<void(const progress_t&)>;

struct download_request_t {
	std::string pdb_name;
	std::string pdb_guid;
	uint32_t    pdb_age = 0;
	std::string server_base;
	std::string cache_root;
};

struct download_result_t {
	bool        ok = false;
	std::string local_path;
	std::string error;
	uint64_t    bytes_downloaded = 0;
	bool        from_cache = false;
};

bool resolve_cache_path(const download_request_t& req, std::string& out_path);

bool download_pdb_sync(const download_request_t& req,
                       const progress_callback_t& on_progress,
                       const std::atomic<bool>* cancel,
                       download_result_t& out);

}
