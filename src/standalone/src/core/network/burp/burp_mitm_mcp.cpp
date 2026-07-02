#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_mitm_mcp.hpp"

#include "../cert_generator.hpp"
#include "../flow_store.hpp"
#include "../map_resource.hpp"
#include "../mitm_proxy.hpp"
#include "../protocol_parser.hpp"
#include "../server_replay.hpp"
#include "../tls_policy.hpp"
#include "../../../helpers/diag_log.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace mitm_mcp {

namespace {

using json = nlohmann::json;
using tool_def_t = mcp_standalone::tool_def_t;
using tool_result_t = mcp_standalone::tool_result_t;

struct reverse_target_t {
    std::string host;
    uint16_t port = 0;
};

struct listener_t {
    uint64_t id = 0;
    std::string bind_addr = "127.0.0.1";
    uint16_t bind_port = 0;
    std::string mode = "regular";
    bool decode_tls = true;
    bool enable_h2 = true;
    mitm_proxy::upstream_proxy_config upstream;
    bool attached_to_core_proxy = false;
};

struct proxy_auth_t {
    bool enabled = false;
    std::string realm = "AiDA Proxy";
    std::string username;
    std::string password;
    std::string password_hash;
};

struct sticky_session_t {
    bool enabled = false;
    uint64_t rule_id = 0;
    bool auto_run_macros = true;
};

struct plan2_state_t {
    std::mutex mutex;
    std::string mode = "regular";
    reverse_target_t reverse_target;
    uint16_t transparent_port = 443;
    uint64_t next_listener_id = 1;
    std::vector<listener_t> listeners;
    proxy_auth_t auth;
    sticky_session_t sticky;
    std::atomic<uint64_t> replay_batches{0};
    std::atomic<uint64_t> replay_requests{0};
    std::atomic<uint64_t> replay_success{0};
    std::atomic<uint64_t> replay_errors{0};
};

plan2_state_t& state()
{
    static plan2_state_t s;
    return s;
}

std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool loopback_bind_addr(const std::string& bind_addr)
{
    const std::string a = lower_ascii(bind_addr);
    return a.empty() || a == "127.0.0.1" || a == "localhost" || a == "::1" || a == "[::1]";
}

bool json_u64(const json& j, uint64_t& out)
{
    if (j.is_number_unsigned()) {
        out = j.get<uint64_t>();
        return true;
    }
    if (j.is_number_integer()) {
        const int64_t v = j.get<int64_t>();
        if (v >= 0) {
            out = static_cast<uint64_t>(v);
            return true;
        }
    }
    return false;
}

bool json_u16(const json& j, uint16_t& out)
{
    uint64_t v = 0;
    if (!json_u64(j, v) || v == 0 || v > 65535)
        return false;
    out = static_cast<uint16_t>(v);
    return true;
}

bool json_int_bounded(const json& j, int& out, int min_v, int max_v)
{
    if (!j.is_number_integer())
        return false;
    const int v = j.get<int>();
    if (v < min_v || v > max_v)
        return false;
    out = v;
    return true;
}

std::vector<uint64_t> json_ids(const json& p, const char* name)
{
    std::vector<uint64_t> ids;
    if (!p.contains(name) || !p[name].is_array())
        return ids;
    for (const auto& item : p[name]) {
        uint64_t id = 0;
        if (json_u64(item, id) && id != 0)
            ids.push_back(id);
    }
    return ids;
}

std::string base64_encode(const std::vector<uint8_t>& data)
{
    static const char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < data.size()) {
        const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                           (static_cast<uint32_t>(data[i + 1]) << 8) |
                           static_cast<uint32_t>(data[i + 2]);
        out.push_back(alpha[(v >> 18) & 0x3F]);
        out.push_back(alpha[(v >> 12) & 0x3F]);
        out.push_back(alpha[(v >> 6) & 0x3F]);
        out.push_back(alpha[v & 0x3F]);
        i += 3;
    }
    if (i < data.size()) {
        const size_t rem = data.size() - i;
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        if (rem > 1)
            v |= static_cast<uint32_t>(data[i + 1]) << 8;
        out.push_back(alpha[(v >> 18) & 0x3F]);
        out.push_back(alpha[(v >> 12) & 0x3F]);
        out.push_back(rem > 1 ? alpha[(v >> 6) & 0x3F] : '=');
        out.push_back('=');
    }
    return out;
}

std::string sha256_hex(const std::string& text)
{
    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digest_len = 0;
    if (EVP_Digest(text.data(), text.size(), digest, &digest_len, EVP_sha256(), nullptr) != 1 || digest_len == 0)
        return {};
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digest_len; ++i)
        os << std::setw(2) << static_cast<unsigned>(digest[i]);
    return os.str();
}

bool valid_mode(const std::string& mode)
{
    return mode == "regular" || mode == "reverse" || mode == "transparent" || mode == "socks5";
}

bool valid_tls_version(const std::string& v)
{
    return v == "tls1.0" || v == "tls1.1" || v == "tls1.2" || v == "tls1.3";
}

mitm_proxy::proxy_mode_t proxy_mode_from_string(const std::string& mode)
{
    if (mode == "reverse") return mitm_proxy::proxy_mode_t::reverse;
    if (mode == "transparent") return mitm_proxy::proxy_mode_t::transparent;
    if (mode == "socks5") return mitm_proxy::proxy_mode_t::socks5;
    return mitm_proxy::proxy_mode_t::regular;
}

int tls_version_from_string(const std::string& v)
{
    if (v == "tls1.0") return TLS1_VERSION;
    if (v == "tls1.1") return TLS1_1_VERSION;
    if (v == "tls1.2") return TLS1_2_VERSION;
    if (v == "tls1.3") return TLS1_3_VERSION;
    return 0;
}

std::string join_colon(const std::vector<std::string>& values)
{
    std::ostringstream out;
    for (size_t i = 0; i < values.size(); ++i) {
        if (values[i].empty())
            continue;
        if (out.tellp() > 0)
            out << ':';
        out << values[i];
    }
    return out.str();
}

std::vector<std::string> json_string_array(const json& j)
{
    std::vector<std::string> out;
    if (!j.is_array())
        return out;
    for (const auto& item : j) {
        if (item.is_string())
            out.push_back(item.get<std::string>());
    }
    return out;
}

std::string header_value(const std::vector<protocol_parser::http_header>& headers, const std::string& name)
{
    return protocol_parser::find_header(headers, name);
}

std::vector<uint8_t> selected_body(const mitm_proxy::http_exchange& e, const std::string& side)
{
    if (side == "request")
        return e.request.body;
    return e.response.body;
}

std::string selected_raw(const mitm_proxy::http_exchange& e, const std::string& side)
{
    const auto& bytes = (side == "request") ? e.raw_request : e.raw_response;
    return std::string(bytes.begin(), bytes.end());
}

std::string body_as_text(const std::vector<uint8_t>& body)
{
    return std::string(body.begin(), body.end());
}

std::string hex_dump(const std::vector<uint8_t>& body)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < body.size(); i += 16) {
        out << std::setw(8) << i << "  ";
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < body.size())
                out << std::setw(2) << static_cast<unsigned>(body[i + j]) << ' ';
            else
                out << "   ";
        }
        out << ' ';
        for (size_t j = 0; j < 16 && i + j < body.size(); ++j) {
            const uint8_t c = body[i + j];
            out << (c >= 0x20 && c <= 0x7E ? static_cast<char>(c) : '.');
        }
        if (i + 16 < body.size())
            out << '\n';
    }
    return out.str();
}

std::string format_xml(const std::string& text)
{
    std::ostringstream out;
    int depth = 0;
    for (size_t i = 0; i < text.size();) {
        const size_t lt = text.find('<', i);
        if (lt == std::string::npos) {
            const std::string tail = text.substr(i);
            if (!tail.empty())
                out << std::string(static_cast<size_t>(std::max(depth, 0)) * 2, ' ') << tail;
            break;
        }
        if (lt > i) {
            const std::string value = text.substr(i, lt - i);
            if (value.find_first_not_of(" \t\r\n") != std::string::npos)
                out << std::string(static_cast<size_t>(std::max(depth, 0)) * 2, ' ') << value << '\n';
        }
        const size_t gt = text.find('>', lt);
        if (gt == std::string::npos) {
            out << text.substr(lt);
            break;
        }
        const std::string tag = text.substr(lt, gt - lt + 1);
        const bool closing = tag.size() > 1 && tag[1] == '/';
        const bool self_closing = tag.size() > 2 && tag[tag.size() - 2] == '/';
        if (closing && depth > 0)
            --depth;
        out << std::string(static_cast<size_t>(std::max(depth, 0)) * 2, ' ') << tag << '\n';
        if (!closing && !self_closing && tag.size() > 1 && tag[1] != '?' && tag[1] != '!')
            ++depth;
        i = gt + 1;
    }
    return out.str();
}

std::vector<mitm_proxy::http_exchange> flows_from_params_or_file(const json& p, std::string& error)
{
    if (p.contains("file_path") && p["file_path"].is_string()) {
        flow_serializer::flow_format format = flow_serializer::flow_format::aida_json;
        if (p.contains("format") && !flow_serializer::parse_format(p.value("format", std::string("aida")), format)) {
            error = "invalid_format";
            return {};
        }
        auto loaded = flow_serializer::load_file(p["file_path"].get<std::string>(), format);
        if (!loaded.success) {
            error = loaded.error;
            return {};
        }
        return std::move(loaded.flows);
    }
    const auto ids = json_ids(p, "flow_ids");
    if (!ids.empty())
        return mitm_proxy::get_history_by_ids(ids);
    return {};
}

json upstream_to_json(const mitm_proxy::upstream_proxy_config& u)
{
    std::string type = "none";
    if (u.type == mitm_proxy::upstream_proxy_config::type_t::http_connect)
        type = "http_connect";
    else if (u.type == mitm_proxy::upstream_proxy_config::type_t::socks5)
        type = "socks5";
    return {{"type", type}, {"host", u.host}, {"port", u.port}, {"username_set", !u.username.empty()}, {"password_set", !u.password.empty()}};
}

bool upstream_from_json(const json& j, mitm_proxy::upstream_proxy_config& out)
{
    if (!j.is_object())
        return true;
    const std::string type = j.value("type", std::string("none"));
    if (type == "none" || type.empty()) {
        out.type = mitm_proxy::upstream_proxy_config::type_t::none;
        return true;
    }
    if (type == "http_connect")
        out.type = mitm_proxy::upstream_proxy_config::type_t::http_connect;
    else if (type == "socks5")
        out.type = mitm_proxy::upstream_proxy_config::type_t::socks5;
    else
        return false;
    out.host = j.value("host", std::string());
    if (out.host.empty() || !j.contains("port") || !json_u16(j["port"], out.port))
        return false;
    out.username = j.value("username", std::string());
    out.password = j.value("password", std::string());
    return true;
}

json state_summary_unlocked()
{
    auto& st = state();
    json listeners = json::array();
    for (const auto& l : st.listeners) {
        listeners.push_back({
            {"id", l.id},
            {"bind_addr", l.bind_addr},
            {"bind_port", l.bind_port},
            {"mode", l.mode},
            {"decode_tls", l.decode_tls},
            {"enable_h2", l.enable_h2},
            {"attached_to_core_proxy", l.attached_to_core_proxy},
            {"upstream", upstream_to_json(l.upstream)}
        });
    }
    json policies = json::array();
    for (const auto& p : tls_policy::policies()) {
        policies.push_back({
            {"name", p.name},
            {"host_pattern", p.host_regex},
            {"ignore_cert_errors", p.ignore_cert_errors},
            {"cipher_list", p.cipher_list},
            {"ciphersuites", p.ciphersuites},
            {"pin_count", p.upstream_cert_sha256_pins.size()}
        });
    }
    json local_maps = json::array();
    for (const auto& m : map_resource::list_local_rules())
        local_maps.push_back({{"id", m.id}, {"url_pattern", m.url_prefix}, {"file_path", m.local_path}, {"content_type", m.content_type}, {"status_code", m.status_code}});
    json remote_maps = json::array();
    for (const auto& m : map_resource::list_remote_rules())
        remote_maps.push_back({{"id", m.id}, {"url_pattern", m.url_prefix}, {"remote_url", m.remote_prefix}, {"preserve_host_header", !m.update_host_header}});
    const auto replay_rules = server_replay::list_rules();
    json out;
    out["mode"] = st.mode;
    out["reverse_target"] = {{"host", st.reverse_target.host}, {"port", st.reverse_target.port}};
    out["transparent_port"] = st.transparent_port;
    out["listeners"] = std::move(listeners);
    out["tls_policies"] = std::move(policies);
    out["server_replay"] = {{"enabled", server_replay::is_enabled()}, {"rule_count", replay_rules.size()}};
    out["map_local"] = std::move(local_maps);
    out["map_remote"] = std::move(remote_maps);
    out["proxy_auth"] = {{"enabled", st.auth.enabled}, {"realm", st.auth.realm}, {"username_set", !st.auth.username.empty()}, {"password_hash_set", !st.auth.password_hash.empty()}};
    out["sticky_session"] = {{"enabled", st.sticky.enabled}, {"rule_id", st.sticky.rule_id}, {"auto_run_macros", st.sticky.auto_run_macros}};
    out["replay_counters"] = {{"batches", st.replay_batches.load()}, {"requests", st.replay_requests.load()}, {"success", st.replay_success.load()}, {"errors", st.replay_errors.load()}};
    return out;
}

json state_summary()
{
    auto& st = state();
    std::lock_guard<std::mutex> lock(st.mutex);
    return state_summary_unlocked();
}

tool_result_t tool_proxy_set_mode(const json& p)
{
    const std::string mode = p.value("mode", std::string());
    if (!valid_mode(mode))
        return tool_result_t::error("invalid_mode");
    reverse_target_t reverse;
    uint16_t transparent_port = 443;
    if (mode == "reverse") {
        if (!p.contains("reverse_target") || !p["reverse_target"].is_object())
            return tool_result_t::error("missing_reverse_target");
        reverse.host = p["reverse_target"].value("host", std::string());
        if (reverse.host.empty() || !p["reverse_target"].contains("port") || !json_u16(p["reverse_target"]["port"], reverse.port))
            return tool_result_t::error("invalid_reverse_target");
    }
    if (mode == "transparent" && p.contains("transparent_port") && !json_u16(p["transparent_port"], transparent_port))
        return tool_result_t::error("invalid_transparent_port");
    auto& st = state();
    std::lock_guard<std::mutex> lock(st.mutex);
    st.mode = mode;
    st.reverse_target = reverse;
    st.transparent_port = transparent_port;
    json out = state_summary_unlocked();
    out["applied_to_core_proxy"] = false;
    out["core_proxy_running"] = mitm_proxy::is_running();
    return tool_result_t::ok(out);
}

tool_result_t tool_proxy_start_listener(const json& p)
{
    listener_t listener;
    listener.bind_addr = p.value("bind_addr", std::string("127.0.0.1"));
    if (!loopback_bind_addr(listener.bind_addr))
        return tool_result_t::error("bind_addr_must_be_loopback");
    if (!p.contains("bind_port") || !json_u16(p["bind_port"], listener.bind_port))
        return tool_result_t::error("invalid_bind_port");
    listener.mode = p.value("mode", std::string("regular"));
    if (!valid_mode(listener.mode))
        return tool_result_t::error("invalid_mode");
    listener.decode_tls = p.value("decode_tls", true);
    listener.enable_h2 = p.value("enable_h2", true);
    if (p.contains("upstream") && !upstream_from_json(p["upstream"], listener.upstream))
        return tool_result_t::error("invalid_upstream");
    reverse_target_t inline_reverse;
    if (listener.mode == "reverse" && p.contains("reverse_target")) {
        if (!p["reverse_target"].is_object())
            return tool_result_t::error("invalid_reverse_target");
        inline_reverse.host = p["reverse_target"].value("host", std::string());
        if (inline_reverse.host.empty() || !p["reverse_target"].contains("port") || !json_u16(p["reverse_target"]["port"], inline_reverse.port))
            return tool_result_t::error("invalid_reverse_target");
    }
    bool attached = false;
    mitm_proxy::proxy_config cfg;
    cfg.bind_addr = listener.bind_addr;
    cfg.bind_port = listener.bind_port;
    cfg.mode = proxy_mode_from_string(listener.mode);
    cfg.decode_tls = listener.decode_tls;
    cfg.enable_h2 = listener.enable_h2;
    cfg.upstream = listener.upstream;
    cfg.use_wfp_redirect = listener.mode == "transparent";
    {
        auto& st = state();
        std::lock_guard<std::mutex> lock(st.mutex);
        cfg.redirect_target_port = st.transparent_port;
        cfg.enable_sticky_sessions = st.sticky.enabled;
        cfg.require_proxy_auth = st.auth.enabled;
        cfg.proxy_auth_username = st.auth.username;
        cfg.proxy_auth_password = st.auth.password;
        if (listener.mode == "reverse") {
            cfg.reverse_target_host = inline_reverse.host.empty() ? st.reverse_target.host : inline_reverse.host;
            cfg.reverse_target_port = inline_reverse.port == 0 ? st.reverse_target.port : inline_reverse.port;
            if (cfg.reverse_target_host.empty() || cfg.reverse_target_port == 0)
                return tool_result_t::error("missing_reverse_target");
            cfg.reverse_target_tls = cfg.reverse_target_port == 443;
        }
    }
    uint64_t core_listener_id = 0;
    if (!mitm_proxy::is_running()) {
        attached = mitm_proxy::start(cfg);
        if (!attached)
            return tool_result_t::error("proxy_listener_start_failed");
        core_listener_id = 1;
    } else {
        attached = mitm_proxy::start_listener(cfg, &core_listener_id);
        if (!attached)
            return tool_result_t::error("proxy_listener_start_failed");
    }
    auto& st = state();
    std::lock_guard<std::mutex> lock(st.mutex);
    listener.id = core_listener_id == 0 ? st.next_listener_id++ : core_listener_id;
    listener.attached_to_core_proxy = attached;
    st.listeners.push_back(listener);
    json out = state_summary_unlocked();
    out["listener_id"] = listener.id;
    out["attached_to_core_proxy"] = attached;
    out["core_proxy_running"] = mitm_proxy::is_running();
    return tool_result_t::ok(out);
}

tool_result_t tool_proxy_set_tls_policy(const json& p)
{
    tls_policy::host_policy_t policy;
    policy.name = p.value("name", std::string("mcp"));
    policy.host_regex = p.value("host_pattern", std::string());
    if (policy.host_regex.empty())
        return tool_result_t::error("missing_host_pattern");
    try {
        std::regex re(policy.host_regex);
        (void)re;
    } catch (const std::exception& e) {
        return tool_result_t::error(std::string("invalid_host_pattern: ") + e.what());
    }
    const std::string min_version = p.value("min_version", std::string("tls1.2"));
    const std::string max_version = p.value("max_version", std::string());
    if (!valid_tls_version(min_version) || (!max_version.empty() && !valid_tls_version(max_version)))
        return tool_result_t::error("invalid_tls_version");
    policy.min_tls_version = tls_version_from_string(min_version);
    policy.max_tls_version = max_version.empty() ? 0 : tls_version_from_string(max_version);
    policy.ignore_cert_errors = p.value("ignore_cert_errors", false);
    const auto cipher_suites = p.contains("cipher_suites") ? json_string_array(p["cipher_suites"]) : std::vector<std::string>();
    policy.cipher_list = join_colon(cipher_suites);
    policy.ciphersuites = policy.cipher_list;
    if (p.contains("upstream_cert_sha256_pins"))
        policy.upstream_cert_sha256_pins = json_string_array(p["upstream_cert_sha256_pins"]);
    if (!tls_policy::add_policy(policy))
        return tool_result_t::error("tls_policy_rejected");
    cert_generator::clear_ssl_ctx_cache();
    json out = state_summary();
    out["ssl_ctx_cache_cleared"] = true;
    out["generation"] = tls_policy::generation();
    return tool_result_t::ok(out);
}

tool_result_t tool_flow_save(const json& p)
{
    const std::string file_path = p.value("file_path", std::string());
    if (file_path.empty())
        return tool_result_t::error("missing_file_path");
    flow_serializer::flow_format format = flow_serializer::flow_format::aida_json;
    if (!flow_serializer::parse_format(p.value("format", std::string("aida")), format))
        return tool_result_t::error("invalid_format");
    const auto ids = json_ids(p, "flow_ids");
    auto saved = flow_store::save_history(file_path, format, ids);
    if (!saved.success)
        return tool_result_t::error("flow_save_failed: " + saved.error);
    json out;
    out["file_path"] = file_path;
    out["format"] = flow_serializer::format_name(format);
    out["requested_count"] = ids.empty() ? json() : json(ids.size());
    out["saved_count"] = saved.flow_count;
    return tool_result_t::ok(out);
}

tool_result_t tool_flow_load(const json& p)
{
    const std::string file_path = p.value("file_path", std::string());
    const bool append = p.value("append", false);
    if (file_path.empty())
        return tool_result_t::error("missing_file_path");
    flow_serializer::flow_format format = flow_serializer::flow_format::aida_json;
    if (!flow_serializer::parse_format(p.value("format", std::string("aida")), format))
        return tool_result_t::error("invalid_format");
    auto loaded = flow_store::load_history(file_path, format, append);
    if (!loaded.success)
        return tool_result_t::error("flow_load_failed: " + loaded.error);
    json out;
    out["file_path"] = file_path;
    out["format"] = flow_serializer::format_name(format);
    out["append"] = append;
    out["loaded_count"] = loaded.flow_count;
    out["history_size"] = mitm_proxy::history_count();
    return tool_result_t::ok(out);
}

tool_result_t tool_client_replay(const json& p)
{
    std::string error;
    auto flows = flows_from_params_or_file(p, error);
    if (!error.empty())
        return tool_result_t::error(error);
    if (flows.empty())
        return tool_result_t::error("no_flows_selected");
    const std::string override_host = p.value("target_host", std::string());
    uint16_t override_port = 0;
    const bool has_override_port = p.contains("target_port") && json_u16(p["target_port"], override_port);
    if (p.contains("target_port") && !has_override_port)
        return tool_result_t::error("invalid_target_port");
    const bool has_tls_override = p.contains("use_tls") && p["use_tls"].is_boolean();
    const bool tls_override = has_tls_override ? p["use_tls"].get<bool>() : false;
    int concurrency = p.value("concurrency", 1);
    int delay_ms = p.value("delay_ms", 0);
    if (concurrency < 1) concurrency = 1;
    if (concurrency > 16) concurrency = 16;
    if (delay_ms < 0) delay_ms = 0;
    if (delay_ms > 60000) delay_ms = 60000;
    const bool stop_on_error = p.value("stop_on_error", false);
    flow_store::client_replay_options options;
    options.flows = std::move(flows);
    options.target_host = override_host;
    options.target_port = has_override_port ? override_port : 0;
    options.override_tls = has_tls_override;
    options.use_tls = tls_override;
    options.concurrency = static_cast<uint32_t>(concurrency);
    options.delay_ms = static_cast<uint32_t>(delay_ms);
    options.stop_on_error = stop_on_error;
    auto replay = flow_store::client_replay(options);
    auto& st = state();
    st.replay_batches.fetch_add(1);
    json results = json::array();
    st.replay_requests.fetch_add(replay.attempted);
    st.replay_success.fetch_add(replay.succeeded);
    st.replay_errors.fetch_add(replay.failed);
    for (const auto& rr : replay.items) {
        json item;
        item["source_flow_id"] = rr.source_flow_id;
        item["success"] = rr.success;
        item["error"] = rr.error;
        item["observed_flow_id"] = rr.exchange.id;
        item["status_code"] = rr.exchange.response.status_code;
        item["latency_ms"] = rr.exchange.latency_ms;
        results.push_back(std::move(item));
    }
    json out;
    out["requested_count"] = replay.items.size();
    out["result_count"] = results.size();
    out["attempted"] = replay.attempted;
    out["succeeded"] = replay.succeeded;
    out["failed"] = replay.failed;
    out["completed"] = replay.completed;
    out["cancelled"] = replay.cancelled;
    out["error"] = replay.error;
    out["results"] = std::move(results);
    out["counters"] = state_summary()["replay_counters"];
    return tool_result_t::ok(out);
}

tool_result_t tool_server_replay_start(const json& p)
{
    const std::string match_by = p.value("match_by", std::string("host_path"));
    if (match_by != "host_path" && match_by != "full_url" && match_by != "host_path_method")
        return tool_result_t::error("invalid_match_by");
    const auto ids = json_ids(p, "flow_ids");
    if (ids.empty())
        return tool_result_t::error("missing_flow_ids");
    auto flows = mitm_proxy::get_history_by_ids(ids);
    if (flows.empty())
        return tool_result_t::error("selected_flows_not_found");
    server_replay::load_options options;
    options.replace_existing = true;
    options.exact_body = match_by == "full_url";
    const size_t added = server_replay::load_from_flows(flows, options);
    server_replay::set_enabled(added > 0);
    json out = state_summary();
    out["flow_ids"] = ids;
    out["rules_added"] = added;
    return added > 0 ? tool_result_t::ok(out) : tool_result_t::error("no_replay_rules_added", out);
}

tool_result_t tool_server_replay_stop(const json&)
{
    server_replay::set_enabled(false);
    server_replay::clear_rules();
    json out = state_summary();
    return tool_result_t::ok(out);
}

tool_result_t tool_map_local_add(const json& p)
{
    map_resource::local_rule rule;
    rule.url_prefix = p.value("url_pattern", std::string());
    rule.local_path = p.value("file_path", std::string());
    rule.content_type = p.value("content_type", std::string());
    rule.label = p.value("label", std::string("mcp-local"));
    if (rule.url_prefix.empty() || rule.local_path.empty())
        return tool_result_t::error("missing_url_pattern_or_file_path");
    if (!std::filesystem::exists(std::filesystem::path(rule.local_path)))
        return tool_result_t::error("file_path_not_found");
    int status_code = 200;
    if (p.contains("status_code") && !json_int_bounded(p["status_code"], status_code, 100, 599))
        return tool_result_t::error("invalid_status_code");
    rule.status_code = static_cast<uint16_t>(status_code);
    if (std::filesystem::is_directory(std::filesystem::path(rule.local_path)))
        rule.kind = map_resource::local_rule_kind::directory_prefix;
    const uint64_t id = map_resource::add_local_rule(rule);
    json out = state_summary();
    out["map_id"] = id;
    return tool_result_t::ok(out);
}

tool_result_t tool_map_remote_add(const json& p)
{
    map_resource::remote_rule rule;
    rule.url_prefix = p.value("url_pattern", std::string());
    rule.remote_prefix = p.value("remote_url", std::string());
    rule.update_host_header = !p.value("preserve_host_header", false);
    rule.label = p.value("label", std::string("mcp-remote"));
    if (rule.url_prefix.empty() || rule.remote_prefix.empty())
        return tool_result_t::error("missing_url_pattern_or_remote_url");
    if (rule.remote_prefix.find("http://") != 0 && rule.remote_prefix.find("https://") != 0)
        return tool_result_t::error("remote_url_must_be_http_or_https");
    const uint64_t id = map_resource::add_remote_rule(rule);
    json out = state_summary();
    out["map_id"] = id;
    return tool_result_t::ok(out);
}

tool_result_t tool_proxy_set_auth(const json& p)
{
    proxy_auth_t auth;
    auth.enabled = p.value("enabled", false);
    auth.realm = p.value("realm", std::string("AiDA Proxy"));
    if (auth.enabled) {
        auth.username = p.value("username", std::string());
        const std::string password = p.value("password", std::string());
        if (auth.username.empty() || password.empty())
            return tool_result_t::error("username_and_password_required_when_enabled");
        auth.password = password;
        auth.password_hash = sha256_hex(auth.username + ":" + auth.realm + ":" + password);
        if (auth.password_hash.empty())
            return tool_result_t::error("password_hash_failed");
    }
    auto& st = state();
    std::lock_guard<std::mutex> lock(st.mutex);
    st.auth = auth;
    json out = state_summary_unlocked();
    out["applies_to_new_listeners"] = true;
    out["core_proxy_running"] = mitm_proxy::is_running();
    return tool_result_t::ok(out);
}

tool_result_t tool_content_view_render(const json& p)
{
    uint64_t flow_id = 0;
    if (!p.contains("flow_id") || !json_u64(p["flow_id"], flow_id) || flow_id == 0)
        return tool_result_t::error("missing_flow_id");
    const std::string view = p.value("view", std::string("raw"));
    const std::string side = p.value("side", std::string("response"));
    if (side != "request" && side != "response")
        return tool_result_t::error("invalid_side");
    const auto flows = mitm_proxy::get_history_by_ids({flow_id});
    if (flows.empty())
        return tool_result_t::error("flow_not_found");
    const auto& flow = flows.front();
    const auto body = selected_body(flow, side);
    std::string rendered;
    std::string encoding = "utf-8";
    if (view == "raw") {
        rendered = selected_raw(flow, side);
    } else if (view == "json") {
        try {
            rendered = json::parse(body_as_text(body)).dump(2);
        } catch (const std::exception& e) {
            return tool_result_t::error(std::string("invalid_json: ") + e.what());
        }
    } else if (view == "xml") {
        rendered = format_xml(body_as_text(body));
    } else if (view == "hex") {
        rendered = hex_dump(body);
        encoding = "hex-dump";
    } else if (view == "form") {
        rendered = body_as_text(body);
    } else if (view == "image" || view == "protobuf") {
        rendered = base64_encode(body);
        encoding = "base64";
    } else {
        return tool_result_t::error("invalid_view");
    }
    json out;
    out["flow_id"] = flow_id;
    out["side"] = side;
    out["view"] = view;
    out["encoding"] = encoding;
    out["length"] = rendered.size();
    out["body_length"] = body.size();
    out["content_type"] = side == "request" ? header_value(flow.request.headers, "Content-Type") : header_value(flow.response.headers, "Content-Type");
    out["rendered"] = rendered;
    return tool_result_t::ok(out);
}

tool_result_t tool_flow_tag(const json& p)
{
    uint64_t flow_id = 0;
    if (!p.contains("flow_id") || !json_u64(p["flow_id"], flow_id) || flow_id == 0)
        return tool_result_t::error("missing_flow_id");
    const std::string action = p.value("action", std::string("list"));
    if (action == "add") {
        const std::string tag = p.value("tag", std::string());
        if (tag.empty())
            return tool_result_t::error("missing_tag");
        if (!mitm_proxy::add_exchange_tag(flow_id, tag))
            return tool_result_t::error("flow_not_found");
    } else if (action == "remove") {
        const std::string tag = p.value("tag", std::string());
        if (tag.empty())
            return tool_result_t::error("missing_tag");
        if (!mitm_proxy::remove_exchange_tag(flow_id, tag))
            return tool_result_t::error("flow_not_found");
    } else if (action != "list") {
        return tool_result_t::error("invalid_action");
    }
    auto flows = mitm_proxy::get_history_by_ids({flow_id});
    if (flows.empty())
        return tool_result_t::error("flow_not_found");
    json out;
    out["flow_id"] = flow_id;
    out["action"] = action;
    out["tags"] = flows.front().tags;
    if (p.contains("color") && p["color"].is_string())
        out["color"] = p["color"].get<std::string>();
    return tool_result_t::ok(out);
}

tool_result_t tool_sticky_session_enable(const json& p)
{
    sticky_session_t sticky;
    sticky.enabled = p.value("enabled", false);
    if (p.contains("rule_id") && !json_u64(p["rule_id"], sticky.rule_id))
        return tool_result_t::error("invalid_rule_id");
    sticky.auto_run_macros = p.value("auto_run_macros", true);
    auto& st = state();
    std::lock_guard<std::mutex> lock(st.mutex);
    st.sticky = sticky;
    json out = state_summary_unlocked();
    out["applies_to_new_listeners"] = true;
    out["core_proxy_running"] = mitm_proxy::is_running();
    return tool_result_t::ok(out);
}

tool_result_t tool_connection_pool_stats(const json&)
{
    const auto stats = mitm_proxy::get_stats();
    const auto pool = mitm_proxy::conn_pool::get_stats();
    auto& st = state();
    json out;
    out["core_proxy_running"] = stats.running;
    out["active_connections"] = stats.active_connections;
    out["history_size"] = stats.history_size;
    out["total_requests"] = stats.total_requests;
    out["idle_total"] = pool.idle_total;
    out["idle_tcp"] = pool.idle_tcp;
    out["idle_tls"] = pool.idle_tls;
    out["acquired"] = pool.acquired;
    out["reused"] = pool.reused;
    out["released"] = pool.released;
    out["closed"] = pool.closed;
    out["evicted"] = pool.evicted;
    out["failed_reuse"] = pool.failed_reuse;
    out["tcp_reused"] = pool.tcp_reused;
    out["tls_reused"] = pool.tls_reused;
    out["max_idle_total"] = pool.max_idle_total;
    out["max_idle_per_key"] = pool.max_idle_per_key;
    out["idle_timeout_ms"] = pool.idle_timeout_ms;
    out["max_age_ms"] = pool.max_age_ms;
    out["replay_requests"] = st.replay_requests.load();
    out["replay_success"] = st.replay_success.load();
    out["replay_errors"] = st.replay_errors.load();
    return tool_result_t::ok(out);
}

tool_result_t tool_cert_status(const json&)
{
    json out;
    out["ready"] = cert_generator::is_ready();
    out["storage_dir"] = cert_generator::get_ca_storage_dir();
    if (cert_generator::is_ready()) {
        const auto& ca = cert_generator::get_root_ca();
        out["valid"] = ca.valid;
        out["installed"] = cert_generator::is_root_ca_installed(ca);
        out["spki_sha256_base64"] = cert_generator::spki_sha256_base64(ca);
    }
    return tool_result_t::ok(out);
}

tool_result_t tool_cert_install_ca(const json&)
{
    if (!cert_generator::is_ready() && !cert_generator::initialize())
        return tool_result_t::error("cert_generator_not_ready");
    const auto& ca = cert_generator::get_root_ca();
    const bool ok = cert_generator::install_root_ca(ca);
    json out = tool_cert_status(json::object()).data;
    out["installed_now"] = ok;
    return ok ? tool_result_t::ok(out) : tool_result_t::error("install_root_ca_failed", out);
}

tool_result_t tool_cert_remove_ca(const json&)
{
    if (!cert_generator::is_ready())
        return tool_result_t::error("cert_generator_not_ready");
    const auto& ca = cert_generator::get_root_ca();
    const bool ok = cert_generator::remove_root_ca(ca);
    json out = tool_cert_status(json::object()).data;
    out["removed_now"] = ok;
    return ok ? tool_result_t::ok(out) : tool_result_t::error("remove_root_ca_failed", out);
}

tool_result_t tool_cert_export_ca(const json& p)
{
    if (!cert_generator::is_ready() && !cert_generator::initialize())
        return tool_result_t::error("cert_generator_not_ready");
    const std::string format = lower_ascii(p.value("format", std::string("pem")));
    const std::string file_path = p.value("file_path", std::string());
    json out;
    out["format"] = format;
    if (format == "pem") {
        std::string pem;
        if (!cert_generator::export_ca_certificate_pem(cert_generator::get_root_ca(), pem))
            return tool_result_t::error("export_pem_failed");
        out["pem"] = pem;
        if (!file_path.empty()) {
            std::filesystem::path fp(file_path);
            std::error_code ec;
            if (!fp.parent_path().empty())
                std::filesystem::create_directories(fp.parent_path(), ec);
            std::ofstream file(file_path, std::ios::binary | std::ios::trunc);
            if (!file)
                return tool_result_t::error("open_failed");
            file << pem;
            out["file_path"] = file_path;
        }
        return tool_result_t::ok(out);
    }
    if (format == "der") {
        std::vector<uint8_t> der;
        if (!cert_generator::export_ca_certificate_der(cert_generator::get_root_ca(), der))
            return tool_result_t::error("export_der_failed");
        out["der_b64"] = base64_encode(der);
        if (!file_path.empty()) {
            std::filesystem::path fp(file_path);
            std::error_code ec;
            if (!fp.parent_path().empty())
                std::filesystem::create_directories(fp.parent_path(), ec);
            std::ofstream file(file_path, std::ios::binary | std::ios::trunc);
            if (!file)
                return tool_result_t::error("open_failed");
            file.write(reinterpret_cast<const char*>(der.data()), static_cast<std::streamsize>(der.size()));
            out["file_path"] = file_path;
        }
        return tool_result_t::ok(out);
    }
    return tool_result_t::error("invalid_format");
}

tool_result_t tool_cert_clear_cache(const json&)
{
    cert_generator::clear_ssl_ctx_cache();
    json out;
    out["ssl_ctx_cache_cleared"] = true;
    return tool_result_t::ok(out);
}

tool_def_t make_tool(const char* name,
                     const char* description,
                     std::vector<mcp_standalone::tool_param_t> params,
                     bool read_only,
                     std::function<tool_result_t(const json&)> handler)
{
    tool_def_t t;
    t.name = name;
    t.description = description;
    t.params = std::move(params);
    t.read_only = read_only;
    t.handler = std::move(handler);
    t.visibility = mcp_standalone::tool_visibility_t::external_visible;
    return t;
}

void register_one(mcp_standalone::server_t& srv, tool_def_t tool)
{
    diag::log_tagged_fmt("mcp_burp", "mitm_plan2_register tool=%s read_only=%d", tool.name.c_str(), tool.read_only ? 1 : 0);
    srv.register_tool(std::move(tool));
}

}

void register_mitm_plan2_tools(mcp_standalone::server_t& srv)
{
    register_one(srv, make_tool("proxy_set_mode", "Switch the MITM proxy operating mode control state.", {{"mode", "string", "regular|reverse|transparent|socks5", true}, {"reverse_target", "object", "Reverse target object with host and port.", false}, {"transparent_port", "number", "Transparent redirect target port.", false}}, false, tool_proxy_set_mode));
    register_one(srv, make_tool("proxy_start_listener", "Start or register an MITM proxy listener with independent configuration.", {{"bind_addr", "string", "Loopback bind address.", false}, {"bind_port", "number", "Bind port.", true}, {"mode", "string", "regular|reverse|transparent|socks5", false}, {"decode_tls", "boolean", "Decode TLS traffic.", false}, {"enable_h2", "boolean", "Enable HTTP/2.", false}, {"upstream", "object", "Optional upstream proxy configuration.", false}}, false, tool_proxy_start_listener));
    register_one(srv, make_tool("proxy_set_tls_policy", "Set per-host TLS version and cipher policy for upstream connections.", {{"host_pattern", "string", "Regex host pattern.", true}, {"min_version", "string", "tls1.0|tls1.1|tls1.2|tls1.3", false}, {"max_version", "string", "Optional max TLS version.", false}, {"cipher_suites", "array", "OpenSSL cipher suite names.", false}, {"ignore_cert_errors", "boolean", "Ignore upstream certificate errors.", false}}, false, tool_proxy_set_tls_policy));
    register_one(srv, make_tool("flow_save", "Save captured flows to disk.", {{"file_path", "string", "Destination file path.", true}, {"flow_ids", "array", "Optional flow ids; empty saves all history.", false}, {"format", "string", "aida|har", false}}, false, tool_flow_save));
    register_one(srv, make_tool("flow_load", "Load serialized flows into proxy history.", {{"file_path", "string", "Source file path.", true}, {"format", "string", "aida|har", false}, {"append", "boolean", "Append instead of replacing history.", false}}, false, tool_flow_load));
    register_one(srv, make_tool("client_replay", "Replay captured requests against original or overridden targets.", {{"flow_ids", "array", "Flow ids to replay.", false}, {"file_path", "string", "Flow file to replay.", false}, {"target_host", "string", "Override target host.", false}, {"target_port", "number", "Override target port.", false}, {"use_tls", "boolean", "Override TLS usage.", false}, {"concurrency", "number", "Worker count, capped at 16.", false}, {"delay_ms", "number", "Delay after each replay.", false}, {"stop_on_error", "boolean", "Stop queue on first error.", false}}, false, tool_client_replay));
    register_one(srv, make_tool("server_replay_start", "Enable server replay control state from saved flows.", {{"flow_ids", "array", "Flow ids whose responses should be served.", true}, {"match_by", "string", "host_path|full_url|host_path_method", false}, {"allow_extra_headers", "boolean", "Allow requests with additional headers.", false}}, false, tool_server_replay_start));
    register_one(srv, make_tool("server_replay_stop", "Disable server replay control state.", {}, false, tool_server_replay_stop));
    register_one(srv, make_tool("map_local_add", "Add a local-file URL prefix mapping rule.", {{"url_pattern", "string", "URL prefix to match.", true}, {"file_path", "string", "Local file path to serve.", true}, {"content_type", "string", "Optional content type override.", false}, {"status_code", "number", "Response status code.", false}}, false, tool_map_local_add));
    register_one(srv, make_tool("map_remote_add", "Add a remote URL prefix rewrite mapping rule.", {{"url_pattern", "string", "URL prefix to match.", true}, {"remote_url", "string", "Replacement remote URL prefix.", true}, {"preserve_host_header", "boolean", "Keep original Host header.", false}}, false, tool_map_remote_add));
    register_one(srv, make_tool("proxy_set_auth", "Configure proxy client authentication control state.", {{"enabled", "boolean", "Enable proxy authentication.", true}, {"realm", "string", "Proxy auth realm.", false}, {"username", "string", "Proxy username.", false}, {"password", "string", "Proxy password.", false}}, false, tool_proxy_set_auth));
    register_one(srv, make_tool("content_view_render", "Render request or response body in a structured content view.", {{"flow_id", "number", "Flow id.", true}, {"view", "string", "raw|json|xml|hex|image|form|protobuf", true}, {"side", "string", "request|response", true}}, true, tool_content_view_render));
    register_one(srv, make_tool("flow_tag", "Add, remove, or list tags on a captured flow.", {{"flow_id", "number", "Flow id.", true}, {"action", "string", "add|remove|list", true}, {"tag", "string", "Tag for add/remove.", false}, {"color", "string", "Optional color metadata for add responses.", false}}, false, tool_flow_tag));
    register_one(srv, make_tool("sticky_session_enable", "Configure sticky session handling control state.", {{"enabled", "boolean", "Enable sticky session handling.", true}, {"rule_id", "number", "Optional session-handler rule id.", false}, {"auto_run_macros", "boolean", "Auto-run macros.", false}}, false, tool_sticky_session_enable));
    register_one(srv, make_tool("connection_pool_stats", "Report upstream connection and replay counters.", {}, true, tool_connection_pool_stats));
    register_one(srv, make_tool("proxy_cert_status", "Report MITM CA readiness and installation status.", {}, true, tool_cert_status));
    register_one(srv, make_tool("proxy_cert_install_ca", "Install the MITM root CA into the current-user trust store.", {}, false, tool_cert_install_ca));
    register_one(srv, make_tool("proxy_cert_remove_ca", "Remove the MITM root CA from the current-user trust store.", {}, false, tool_cert_remove_ca));
    register_one(srv, make_tool("proxy_cert_export_ca", "Export the MITM root CA as PEM or DER.", {{"format", "string", "pem|der", false}, {"file_path", "string", "Optional destination path.", false}}, false, tool_cert_export_ca));
    register_one(srv, make_tool("proxy_cert_clear_cache", "Clear generated per-domain SSL_CTX cache.", {}, false, tool_cert_clear_cache));
}

}
}
}
