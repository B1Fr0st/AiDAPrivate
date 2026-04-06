#include "script_engine.hpp"


#define SOL_ALL_SAFETIES_ON 1
#include <sol/sol.hpp>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace script_engine {


static std::mutex                    g_mutex;
static std::unique_ptr<sol::state>   g_lua;
static std::atomic<bool>             g_initialized{false};
static std::map<std::string, script_info> g_scripts;
static std::deque<log_entry>         g_log;
static constexpr size_t              MAX_LOG_ENTRIES = 4096;


static uint64_t now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}


static void add_log(const std::string& script, const std::string& level,
                    const std::string& msg) {
    log_entry e;
    e.timestamp   = now_ms();
    e.script_name = script;
    e.level       = level;
    e.message     = msg;
    g_log.push_back(std::move(e));
    while (g_log.size() > MAX_LOG_ENTRIES) g_log.pop_front();
}


static std::string current_script_context;

static void lua_log_info(const std::string& msg) {
    add_log(current_script_context, "info", msg);
}

static void lua_log_warn(const std::string& msg) {
    add_log(current_script_context, "warn", msg);
}

static void lua_log_error(const std::string& msg) {
    add_log(current_script_context, "error", msg);
}


static std::string lua_base64_encode(const std::string& input) {
    auto result = decoder_pipeline::apply_single("base64_encode",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_base64_decode(const std::string& input) {
    auto result = decoder_pipeline::apply_single("base64_decode",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_hex_encode(const std::string& input) {
    auto result = decoder_pipeline::apply_single("hex_encode",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_hex_decode(const std::string& input) {
    auto result = decoder_pipeline::apply_single("hex_decode",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_url_encode(const std::string& input) {
    auto result = decoder_pipeline::apply_single("url_encode",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_url_decode(const std::string& input) {
    auto result = decoder_pipeline::apply_single("url_decode",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_md5(const std::string& input) {
    auto result = decoder_pipeline::apply_single("md5",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_sha256(const std::string& input) {
    auto result = decoder_pipeline::apply_single("sha256",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_gzip_decompress(const std::string& input) {
    auto result = decoder_pipeline::apply_single("gzip_decompress",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_gzip_compress(const std::string& input) {
    auto result = decoder_pipeline::apply_single("gzip_compress",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_xor_bytes(const std::string& data, const std::string& key_hex) {
    std::map<std::string, std::string> params = { {"key", key_hex} };
    auto result = decoder_pipeline::apply_single("xor",
        std::vector<uint8_t>(data.begin(), data.end()), params);
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static std::string lua_json_beautify(const std::string& input) {
    auto result = decoder_pipeline::apply_single("json_beautify",
        std::vector<uint8_t>(input.begin(), input.end()));
    if (!result.success) return "";
    return std::string(result.data.begin(), result.data.end());
}

static bool lua_regex_match(const std::string& text, const std::string& pattern) {


    try {
        sol::state_view lua(*g_lua);
        auto result = lua["string"]["match"](text, pattern);
        return result.valid() && result.get_type() != sol::type::lua_nil;
    } catch (...) {
        return false;
    }
}

static sol::table lua_regex_find(const std::string& text, const std::string& pattern) {
    sol::state_view lua(*g_lua);
    sol::table results = lua.create_table();
    try {

        auto gmatch = lua["string"]["gmatch"];
        auto iter = gmatch(text, pattern);
        int idx = 1;
        while (true) {
            auto match_result = iter();
            if (!match_result.valid() || match_result.get_type() == sol::type::lua_nil) break;
            results[idx++] = match_result.get<std::string>();
        }
    } catch (...) {

    }
    return results;
}


static void register_usertypes(sol::state& lua) {

    lua.new_usertype<hook_request_data>("Request",
        "method",   &hook_request_data::method,
        "uri",      &hook_request_data::uri,
        "host",     &hook_request_data::host,
        "port",     &hook_request_data::port,
        "is_tls",   &hook_request_data::is_tls,
        "headers",  &hook_request_data::headers,
        "body",     &hook_request_data::body,
        "modified", &hook_request_data::modified,
        "dropped",  &hook_request_data::dropped,
        "get_header", [](hook_request_data& self, const std::string& name) -> std::string {
            auto it = self.headers.find(name);
            return (it != self.headers.end()) ? it->second : "";
        },
        "set_header", [](hook_request_data& self, const std::string& name, const std::string& value) {
            self.headers[name] = value;
            self.modified = true;
        },
        "remove_header", [](hook_request_data& self, const std::string& name) {
            self.headers.erase(name);
            self.modified = true;
        },
        "get_body_string", [](hook_request_data& self) -> std::string {
            return std::string(self.body.begin(), self.body.end());
        },
        "set_body", [](hook_request_data& self, const std::string& body) {
            self.body.assign(body.begin(), body.end());
            self.modified = true;
        },
        "drop", [](hook_request_data& self) { self.dropped = true; }
    );


    lua.new_usertype<hook_response_data>("Response",
        "status_code", &hook_response_data::status_code,
        "reason",      &hook_response_data::reason,
        "headers",     &hook_response_data::headers,
        "body",        &hook_response_data::body,
        "latency_ms",  &hook_response_data::latency_ms,
        "modified",    &hook_response_data::modified,
        "dropped",     &hook_response_data::dropped,
        "get_header", [](hook_response_data& self, const std::string& name) -> std::string {
            auto it = self.headers.find(name);
            return (it != self.headers.end()) ? it->second : "";
        },
        "set_header", [](hook_response_data& self, const std::string& name, const std::string& value) {
            self.headers[name] = value;
            self.modified = true;
        },
        "get_body_string", [](hook_response_data& self) -> std::string {
            return std::string(self.body.begin(), self.body.end());
        },
        "set_body", [](hook_response_data& self, const std::string& body) {
            self.body.assign(body.begin(), body.end());
            self.modified = true;
        },
        "drop", [](hook_response_data& self) { self.dropped = true; }
    );


    lua.new_usertype<hook_ws_frame_data>("WebSocketFrame",
        "opcode",      &hook_ws_frame_data::opcode,
        "from_server", &hook_ws_frame_data::from_server,
        "payload",     &hook_ws_frame_data::payload,
        "host",        &hook_ws_frame_data::host,
        "modified",    &hook_ws_frame_data::modified,
        "dropped",     &hook_ws_frame_data::dropped,
        "get_text", [](hook_ws_frame_data& self) -> std::string {
            return std::string(self.payload.begin(), self.payload.end());
        },
        "set_payload", [](hook_ws_frame_data& self, const std::string& data) {
            self.payload.assign(data.begin(), data.end());
            self.modified = true;
        },
        "drop", [](hook_ws_frame_data& self) { self.dropped = true; }
    );


    lua.new_usertype<hook_packet_data>("Packet",
        "pid",       &hook_packet_data::pid,
        "protocol",  &hook_packet_data::protocol,
        "direction", &hook_packet_data::direction,
        "src_port",  &hook_packet_data::src_port,
        "dst_port",  &hook_packet_data::dst_port,
        "src_addr",  &hook_packet_data::src_addr,
        "dst_addr",  &hook_packet_data::dst_addr,
        "payload",   &hook_packet_data::payload,
        "dropped",   &hook_packet_data::dropped,
        "get_data", [](hook_packet_data& self) -> std::string {
            return std::string(self.payload.begin(), self.payload.end());
        },
        "drop", [](hook_packet_data& self) { self.dropped = true; }
    );


    lua.new_usertype<hook_dns_data>("DnsQuery",
        "pid",           &hook_dns_data::pid,
        "domain",        &hook_dns_data::domain,
        "query_type",    &hook_dns_data::query_type,
        "resolved_addr", &hook_dns_data::resolved_addr,
        "response_code", &hook_dns_data::response_code,
        "blocked",       &hook_dns_data::blocked,
        "spoof_addr",    &hook_dns_data::spoof_addr,
        "block", [](hook_dns_data& self) { self.blocked = true; },
        "spoof", [](hook_dns_data& self, const std::string& addr) {
            self.spoof_addr = addr;
        }
    );


    lua.new_usertype<hook_connection_data>("Connection",
        "pid",          &hook_connection_data::pid,
        "process_name", &hook_connection_data::process_name,
        "local_addr",   &hook_connection_data::local_addr,
        "local_port",   &hook_connection_data::local_port,
        "remote_addr",  &hook_connection_data::remote_addr,
        "remote_port",  &hook_connection_data::remote_port,
        "protocol",     &hook_connection_data::protocol,
        "is_tls",       &hook_connection_data::is_tls,
        "blocked",      &hook_connection_data::blocked,
        "block", [](hook_connection_data& self) { self.blocked = true; }
    );
}


static void register_api(sol::state& lua) {

    lua.set_function("log",   lua_log_info);
    lua.set_function("warn",  lua_log_warn);
    lua.set_function("error_log", lua_log_error);


    lua.set_function("print", [](sol::variadic_args va) {
        std::string msg;
        for (auto v : va) {
            if (!msg.empty()) msg += "\t";
            msg += v.as<std::string>();
        }
        lua_log_info(msg);
    });


    lua.set_function("base64_encode",  lua_base64_encode);
    lua.set_function("base64_decode",  lua_base64_decode);
    lua.set_function("hex_encode",     lua_hex_encode);
    lua.set_function("hex_decode",     lua_hex_decode);
    lua.set_function("url_encode",     lua_url_encode);
    lua.set_function("url_decode",     lua_url_decode);
    lua.set_function("json_beautify",  lua_json_beautify);


    lua.set_function("md5",    lua_md5);
    lua.set_function("sha256", lua_sha256);


    lua.set_function("gzip",   lua_gzip_compress);
    lua.set_function("gunzip", lua_gzip_decompress);


    lua.set_function("xor_bytes", lua_xor_bytes);


    lua.set_function("regex_match", lua_regex_match);
    lua.set_function("regex_find",  lua_regex_find);


    lua.set_function("bytes_to_string", [](const std::vector<uint8_t>& bytes) -> std::string {
        return std::string(bytes.begin(), bytes.end());
    });

    lua.set_function("string_to_bytes", [](const std::string& s) -> std::vector<uint8_t> {
        return std::vector<uint8_t>(s.begin(), s.end());
    });


    lua.set_function("decode", [](const std::string& transform_id,
                                  const std::string& input,
                                  sol::optional<sol::table> params_table) -> std::string {
        std::map<std::string, std::string> params;
        if (params_table) {
            for (auto& [k, v] : *params_table) {
                params[k.as<std::string>()] = v.as<std::string>();
            }
        }
        auto result = decoder_pipeline::apply_single(transform_id,
            std::vector<uint8_t>(input.begin(), input.end()), params);
        if (!result.success) return std::string("[error: " + result.error + "]");
        return std::string(result.data.begin(), result.data.end());
    });


    lua.set_function("time_ms", now_ms);


    lua["_hooks"] = lua.create_table();

    lua.set_function("register_hook", [](const std::string& hook_name, sol::function fn) {
        if (!g_lua) return;
        sol::table hooks = (*g_lua)["_hooks"];
        if (!hooks[hook_name].valid() || hooks[hook_name].get_type() != sol::type::table) {
            hooks[hook_name] = g_lua->create_table();
        }
        sol::table hook_list = hooks[hook_name];
        hook_list[hook_list.size() + 1] = fn;
    });


    for (int i = 0; i < static_cast<int>(hook_type::COUNT); ++i) {
        auto ht = static_cast<hook_type>(i);
        std::string name = hook_type_name(ht);
        lua.set_function(name, [name](sol::function fn) {
            if (!g_lua) return;
            sol::table hooks = (*g_lua)["_hooks"];
            if (!hooks[name].valid() || hooks[name].get_type() != sol::type::table) {
                hooks[name] = g_lua->create_table();
            }
            sol::table hook_list = hooks[name];
            hook_list[hook_list.size() + 1] = fn;
        });
    }
}


static void apply_sandbox(sol::state& lua) {

    lua["io"]        = sol::lua_nil;
    lua["os"]["execute"] = sol::lua_nil;
    lua["os"]["exit"]    = sol::lua_nil;
    lua["os"]["remove"]  = sol::lua_nil;
    lua["os"]["rename"]  = sol::lua_nil;
    lua["os"]["tmpname"] = sol::lua_nil;
    lua["os"]["getenv"]  = sol::lua_nil;
    lua["loadfile"]  = sol::lua_nil;
    lua["dofile"]    = sol::lua_nil;


    lua_sethook(lua.lua_state(), [](lua_State* L, lua_Debug*) {
        luaL_error(L, "Script exceeded instruction limit (possible infinite loop)");
    }, LUA_MASKCOUNT, 10'000'000);
}


bool initialize() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_initialized.load()) return true;

    g_lua = std::make_unique<sol::state>();
    g_lua->open_libraries(
        sol::lib::base,
        sol::lib::string,
        sol::lib::table,
        sol::lib::math,
        sol::lib::utf8,
        sol::lib::os
    );

    register_usertypes(*g_lua);
    register_api(*g_lua);
    apply_sandbox(*g_lua);

    g_initialized.store(true);
    add_log("engine", "info", "Script engine initialized (Lua 5.4 + sol2)");
    return true;
}

void shutdown() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_initialized.load()) return;

    g_scripts.clear();
    g_log.clear();
    g_lua.reset();
    g_initialized.store(false);
}

bool is_initialized() {
    return g_initialized.load();
}

bool load_script(const std::string& path) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_lua) return false;


    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    std::string source((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();


    std::filesystem::path p(path);
    std::string name = p.stem().string();


    if (g_scripts.count(name)) {


    }

    script_info info;
    info.name      = name;
    info.path      = path;
    info.source    = source;
    info.enabled   = true;
    info.load_time = now_ms();


    auto result = g_lua->safe_script(source, sol::script_pass_on_error);
    if (!result.valid()) {
        sol::error err = result;
        info.last_error = err.what();
        info.loaded = false;
        g_scripts[name] = std::move(info);
        add_log(name, "error", "Failed to load: " + info.last_error);
        return false;
    }

    info.loaded = true;
    g_scripts[name] = std::move(info);
    add_log(name, "info", "Loaded from " + path);
    return true;
}

bool load_script_source(const std::string& name, const std::string& source) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_lua) return false;

    script_info info;
    info.name      = name;
    info.source    = source;
    info.enabled   = true;
    info.load_time = now_ms();

    auto result = g_lua->safe_script(source, sol::script_pass_on_error);
    if (!result.valid()) {
        sol::error err = result;
        info.last_error = err.what();
        info.loaded = false;
        g_scripts[name] = std::move(info);
        add_log(name, "error", "Failed to load: " + info.last_error);
        return false;
    }

    info.loaded = true;
    g_scripts[name] = std::move(info);
    add_log(name, "info", "Loaded from source");
    return true;
}

bool unload_script(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_scripts.find(name);
    if (it == g_scripts.end()) return false;


    (*g_lua)["_hooks"] = g_lua->create_table();
    g_scripts.erase(it);

    for (auto& [sname, sinfo] : g_scripts) {
        if (!sinfo.enabled || !sinfo.loaded) continue;
        auto result = g_lua->safe_script(sinfo.source, sol::script_pass_on_error);
        if (!result.valid()) {
            sol::error err = result;
            sinfo.last_error = err.what();
            sinfo.loaded = false;
        }
    }

    add_log(name, "info", "Unloaded");
    return true;
}

bool reload_script(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_scripts.find(name);
    if (it == g_scripts.end()) return false;

    auto& info = it->second;


    if (!info.path.empty()) {
        std::ifstream file(info.path, std::ios::binary);
        if (file.is_open()) {
            info.source = std::string((std::istreambuf_iterator<char>(file)),
                                       std::istreambuf_iterator<char>());
            file.close();
        }
    }


    (*g_lua)["_hooks"] = g_lua->create_table();
    for (auto& [sname, sinfo] : g_scripts) {
        if (!sinfo.enabled) continue;
        auto result = g_lua->safe_script(sinfo.source, sol::script_pass_on_error);
        if (!result.valid()) {
            sol::error err = result;
            sinfo.last_error = err.what();
            sinfo.loaded = false;
        } else {
            sinfo.loaded = true;
            sinfo.last_error.clear();
        }
    }

    info.load_time = now_ms();
    add_log(name, "info", "Reloaded");
    return true;
}

void set_script_enabled(const std::string& name, bool enabled) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_scripts.find(name);
    if (it == g_scripts.end()) return;
    it->second.enabled = enabled;


    if (g_lua) {
        (*g_lua)["_hooks"] = g_lua->create_table();
        for (auto& [sname, sinfo] : g_scripts) {
            if (!sinfo.enabled || !sinfo.loaded) continue;
            g_lua->safe_script(sinfo.source, sol::script_pass_on_error);
        }
    }
}

std::vector<script_info> get_scripts() {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::vector<script_info> result;
    result.reserve(g_scripts.size());
    for (auto& [name, info] : g_scripts) result.push_back(info);
    return result;
}

const script_info* find_script(const std::string& name) {

    auto it = g_scripts.find(name);
    return (it != g_scripts.end()) ? &it->second : nullptr;
}


template <typename T>
static bool invoke_hook_impl(hook_type type, T& data) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_lua || !g_initialized.load()) return false;

    std::string hook_name = hook_type_name(type);
    sol::table hooks = (*g_lua)["_hooks"];
    if (!hooks.valid()) return false;

    sol::object hook_list_obj = hooks[hook_name];
    if (!hook_list_obj.valid() || hook_list_obj.get_type() != sol::type::table)
        return false;

    sol::table hook_list = hook_list_obj.as<sol::table>();
    bool any_modified = false;

    for (auto& [idx, fn_obj] : hook_list) {
        if (fn_obj.get_type() != sol::type::function) continue;
        sol::function fn = fn_obj.as<sol::function>();


        current_script_context = hook_name;

        auto result = fn(std::ref(data));
        if (!result.valid()) {
            sol::error err = result;
            add_log(hook_name, "error", "Hook error: " + std::string(err.what()));
        }
    }


    (void)any_modified;
    return true;
}

bool invoke_hook(hook_type type, hook_request_data& data)    { return invoke_hook_impl(type, data); }
bool invoke_hook(hook_type type, hook_response_data& data)   { return invoke_hook_impl(type, data); }
bool invoke_hook(hook_type type, hook_ws_frame_data& data)   { return invoke_hook_impl(type, data); }
bool invoke_hook(hook_type type, hook_packet_data& data)     { return invoke_hook_impl(type, data); }
bool invoke_hook(hook_type type, hook_dns_data& data)        { return invoke_hook_impl(type, data); }
bool invoke_hook(hook_type type, hook_connection_data& data) { return invoke_hook_impl(type, data); }


std::string execute(const std::string& code) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_lua) return "[error: engine not initialized]";

    current_script_context = "console";

    auto result = g_lua->safe_script(code, sol::script_pass_on_error);
    if (!result.valid()) {
        sol::error err = result;
        return std::string("[error: ") + err.what() + "]";
    }


    if (result.get_type() != sol::type::lua_nil) {
        try {
            sol::object obj = result;
            if (obj.is<std::string>()) return obj.as<std::string>();
            if (obj.is<double>()) return std::to_string(obj.as<double>());
            if (obj.is<bool>()) return obj.as<bool>() ? "true" : "false";
            return "[" + std::string(sol::type_name(g_lua->lua_state(), obj.get_type())) + "]";
        } catch (...) {
            return "[ok]";
        }
    }
    return "";
}


std::vector<log_entry> get_log(size_t max_count) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (max_count == 0 || max_count >= g_log.size())
        return std::vector<log_entry>(g_log.begin(), g_log.end());
    return std::vector<log_entry>(g_log.end() - max_count, g_log.end());
}

void clear_log() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_log.clear();
}


std::vector<api_function> get_api_listing() {
    return {
        { "log",            "log(msg)",                         "Log an info message" },
        { "warn",           "warn(msg)",                        "Log a warning message" },
        { "error_log",      "error_log(msg)",                   "Log an error message" },
        { "print",          "print(...)",                       "Print values (goes to script log)" },
        { "base64_encode",  "base64_encode(str) -> str",        "Base64 encode a string" },
        { "base64_decode",  "base64_decode(str) -> str",        "Base64 decode a string" },
        { "hex_encode",     "hex_encode(str) -> str",           "Hex encode bytes" },
        { "hex_decode",     "hex_decode(str) -> str",           "Hex decode a string" },
        { "url_encode",     "url_encode(str) -> str",           "URL percent-encode" },
        { "url_decode",     "url_decode(str) -> str",           "URL percent-decode" },
        { "md5",            "md5(str) -> str",                  "MD5 hash (hex output)" },
        { "sha256",         "sha256(str) -> str",               "SHA-256 hash (hex output)" },
        { "gzip",           "gzip(str) -> str",                 "Gzip compress" },
        { "gunzip",         "gunzip(str) -> str",               "Gzip decompress" },
        { "xor_bytes",      "xor_bytes(data, key_hex) -> str",  "XOR with hex key" },
        { "json_beautify",  "json_beautify(str) -> str",        "Pretty-print JSON" },
        { "regex_match",    "regex_match(text, pattern) -> bool","Lua pattern match" },
        { "regex_find",     "regex_find(text, pattern) -> table","Find all matches" },
        { "bytes_to_string","bytes_to_string(bytes) -> str",    "Convert byte array to string" },
        { "string_to_bytes","string_to_bytes(str) -> bytes",    "Convert string to byte array" },
        { "decode",         "decode(id, input, params?) -> str", "Run decoder pipeline transform" },
        { "time_ms",        "time_ms() -> number",              "Current time in milliseconds" },
        { "register_hook",  "register_hook(name, fn)",          "Register a hook callback" },
        { "on_request",     "on_request(fn(req))",              "Hook: HTTP request intercepted" },
        { "on_response",    "on_response(fn(resp))",            "Hook: HTTP response received" },
        { "on_websocket_frame","on_websocket_frame(fn(frame))", "Hook: WebSocket frame" },
        { "on_packet",      "on_packet(fn(pkt))",               "Hook: Raw packet captured" },
        { "on_dns",         "on_dns(fn(dns))",                  "Hook: DNS query/response" },
        { "on_connection",  "on_connection(fn(conn))",          "Hook: New connection" },
    };
}

}
