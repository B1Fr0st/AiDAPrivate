#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace network_view { struct artifact_identity_t; }

namespace aida {
namespace burp {
namespace cookie_jar {

bool stage_reviewed_context(const network_view::artifact_identity_t& identity,
                            const std::string& request_path,
                            std::string& unavailable_reason);

enum class same_site_t : int
{
    unset = 0,
    lax   = 1,
    strict = 2,
    none  = 3
};

struct parsed_cookie_t
{
    std::string name;
    std::string value;
    std::string domain;
    std::string path;
    int64_t     expires_unix_ms = 0;
    bool        has_expires = false;
    bool        secure = false;
    bool        http_only = false;
    bool        host_only = false;
    same_site_t same_site = same_site_t::unset;
    int64_t     created_unix_ms = 0;
};

bool initialize();
void shutdown();

bool        parse_set_cookie(const std::string& set_cookie_value, const std::string& request_host, parsed_cookie_t& out);
void        set_cookie(const std::string& host, const parsed_cookie_t& c);
void        ingest_set_cookie_headers(const std::string& request_host,
                                      const std::vector<std::pair<std::string, std::string>>& resp_headers);
std::vector<parsed_cookie_t> cookies_for(const std::string& host, const std::string& path, bool tls);
std::vector<parsed_cookie_t> list_for_host(const std::string& host);
std::vector<parsed_cookie_t> list_all();
std::string                  build_cookie_header(const std::string& host, const std::string& path, bool tls);
bool                         delete_cookie(const std::string& host, const std::string& name, const std::string& path);
void                         clear_for_host(const std::string& host);
void                         clear_all();
bool                         export_netscape(const std::string& file_path);
bool                         import_netscape(const std::string& file_path);
std::string                  storage_path();
bool                         save_to_disk();
bool                         load_from_disk();
std::string                  same_site_str(same_site_t s);
same_site_t                  parse_same_site(const std::string& v);

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

std::string last_error();

}
}
}
