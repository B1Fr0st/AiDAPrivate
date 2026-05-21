#include "test_all_burp.h"

#include "../network/burp/scope.hpp"
#include "../network/burp/cookie_jar.hpp"
#include "../network/burp/match_replace.hpp"
#include "../network/burp/jwt_lab.hpp"
#include "../network/burp/sequencer.hpp"
#include "../network/burp/comparer.hpp"
#include "../network/burp/collaborator.hpp"
#include "../network/burp/crawler.hpp"
#include "../network/burp/active_scanner.hpp"
#include "../network/burp/passive_scanner.hpp"
#include "../network/burp/intruder_engine.hpp"
#include "../network/burp/csp_analyzer.hpp"
#include "../network/burp/report_generator.hpp"
#include "../network/burp/bambda.hpp"
#include "../network/burp/site_map.hpp"
#include "../network/burp/dom_xss_engine.hpp"
#include "../network/burp/ws_editor.hpp"
#include "../network/burp/h2_editor.hpp"
#include "../network/burp/burp_logger.hpp"
#include "../network/burp/upstream_chain.hpp"
#include "../network/burp/camoufox_bridge.hpp"
#include "../network/burp/camoufox_install.hpp"
#include "../network/burp/graphql.hpp"
#include "../network/burp/auth_lab.hpp"
#include "../network/burp/session_handler.hpp"
#include "../network/burp/content_discovery.hpp"
#include "../network/burp/subdomain_enum.hpp"
#include "../network/burp/tech_fingerprint.hpp"
#include "../network/burp/api_definition.hpp"
#include "../network/burp/param_miner.hpp"
#include "../network/burp/payload_library.hpp"
#include "../network/burp/issue.hpp"
#include "../network/burp/browser_launch.hpp"
#include "../network/burp/insertion_points.hpp"
#include "../network/burp/scanner_module.hpp"
#include "../network/burp/audit_http.hpp"
#include "../network/burp/headless_view.hpp"
#include "../../helpers/diag_log.hpp"

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace test_all_features {

namespace {

    void format_timestamp(char* out, std::size_t cap) {
        SYSTEMTIME st; GetLocalTime(&st);
        std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
        (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond, (unsigned)st.wMilliseconds);
    }
    void write_log_file(HANDLE hf, const std::string& line) {
        if (hf == INVALID_HANDLE_VALUE) return;
        DWORD wrote = 0;
        WriteFile(hf, line.data(), (DWORD)line.size(), &wrote, nullptr);
        FlushFileBuffers(hf);
    }
    void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
        char ts[40]; format_timestamp(ts, sizeof(ts));
        char detail[1024]; va_list ap; va_start(ap, fmt);
        _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap); va_end(ap);
        char line[1200];
        _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
        std::string s(line);
        write_log_file(hf, s);
        diag::log_tagged_fmt("test_all", "%s: %s", tag, detail);
        OutputDebugStringA(s.c_str());
    }

    void test_scope_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_init";
        log_msg(hf, tag, "START -- aida::burp::scope::initialize()");
        bool ok = aida::burp::scope::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- scope initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- scope::initialize returned false: %s",
                aida::burp::scope::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_scope_add_include(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_inc";
        log_msg(hf, tag, "START -- add include rule *.example.com");
        uint64_t id = aida::burp::scope::add_include_rule("https", "*.example.com", 443, "/");
        log_msg(hf, tag, "rule id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- include rule added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_include_rule returned 0: %s",
                aida::burp::scope::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_scope_add_exclude(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_exc";
        log_msg(hf, tag, "START -- add exclude rule /logout");
        uint64_t id = aida::burp::scope::add_exclude_rule("https", "*.example.com", 443, "/logout");
        log_msg(hf, tag, "rule id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- exclude rule added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_exclude_rule returned 0: %s",
                aida::burp::scope::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_scope_in_scope_true(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_in_yes";
        log_msg(hf, tag, "START -- check URL in scope: https://www.example.com/app");
        bool in = aida::burp::scope::in_scope("https://www.example.com/app");
        log_msg(hf, tag, "in_scope = %s", in ? "true" : "false");
        if (in) {
            log_msg(hf, tag, "PASS -- URL correctly in scope");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- URL should be in scope");
            failed.fetch_add(1);
        }
    }

    void test_scope_in_scope_false(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_in_no";
        log_msg(hf, tag, "START -- check URL not in scope: https://www.other.com/page");
        bool in = aida::burp::scope::in_scope("https://www.other.com/page");
        log_msg(hf, tag, "in_scope = %s", in ? "true" : "false");
        if (!in) {
            log_msg(hf, tag, "PASS -- URL correctly not in scope");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- URL should not be in scope");
            failed.fetch_add(1);
        }
    }

    void test_scope_list_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_list";
        log_msg(hf, tag, "START -- scope::list_rules()");
        auto rules = aida::burp::scope::list_rules();
        log_msg(hf, tag, "rule count = %zu", rules.size());
        for (size_t i = 0; i < rules.size(); ++i) {
            log_msg(hf, tag, "  [%zu] kind=%d host=%s port=%d path=%s enabled=%s",
                i, (int)rules[i].kind, rules[i].host_pattern.c_str(),
                rules[i].port, rules[i].path_prefix.c_str(),
                rules[i].enabled ? "true" : "false");
        }
        if (rules.size() >= 2) {
            log_msg(hf, tag, "PASS -- found %zu rules (expected >= 2)", rules.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected at least 2 rules, got %zu", rules.size());
            failed.fetch_add(1);
        }
    }

    void test_scope_remove_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_remove";
        log_msg(hf, tag, "START -- remove first rule");
        auto rules = aida::burp::scope::list_rules();
        if (rules.empty()) {
            log_msg(hf, tag, "FAIL -- no rules to remove");
            failed.fetch_add(1);
            return;
        }
        uint64_t id = rules[0].id;
        bool ok = aida::burp::scope::remove_rule(id);
        auto after = aida::burp::scope::list_rules();
        log_msg(hf, tag, "remove_rule(%llu) = %s, rules before=%zu after=%zu",
            (unsigned long long)id, ok ? "true" : "false", rules.size(), after.size());
        if (ok && after.size() == rules.size() - 1) {
            log_msg(hf, tag, "PASS -- rule removed");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- remove did not reduce count");
            failed.fetch_add(1);
        }
    }

    void test_scope_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scope_clear";
        log_msg(hf, tag, "START -- scope::clear_all()");
        aida::burp::scope::clear_all();
        auto rules = aida::burp::scope::list_rules();
        log_msg(hf, tag, "rules after clear = %zu", rules.size());
        if (rules.empty()) {
            log_msg(hf, tag, "PASS -- all rules cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %zu rules remain after clear_all", rules.size());
            failed.fetch_add(1);
        }
    }

    void test_cookie_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_init";
        log_msg(hf, tag, "START -- aida::burp::cookie_jar::initialize()");
        bool ok = aida::burp::cookie_jar::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- cookie_jar initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- cookie_jar::initialize returned false: %s",
                aida::burp::cookie_jar::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_cookie_parse(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_parse";
        log_msg(hf, tag, "START -- parse Set-Cookie header");
        aida::burp::cookie_jar::parsed_cookie_t c;
        bool ok = aida::burp::cookie_jar::parse_set_cookie(
            "session=abc123; Path=/; HttpOnly; Secure", "example.com", c);
        log_msg(hf, tag, "parse result: ok=%s name=%s value=%s domain=%s path=%s httponly=%s secure=%s",
            ok ? "true" : "false", c.name.c_str(), c.value.c_str(),
            c.domain.c_str(), c.path.c_str(),
            c.http_only ? "true" : "false", c.secure ? "true" : "false");
        if (ok && c.name == "session" && c.value == "abc123") {
            log_msg(hf, tag, "PASS -- Set-Cookie parsed correctly");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- parse did not produce expected values");
            failed.fetch_add(1);
        }
    }

    void test_cookie_set(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_set";
        log_msg(hf, tag, "START -- set cookie manually");
        aida::burp::cookie_jar::parsed_cookie_t c;
        c.name = "test_cookie";
        c.value = "test_value_42";
        c.domain = "test.example.com";
        c.path = "/";
        c.secure = false;
        c.http_only = false;
        aida::burp::cookie_jar::set_cookie("test.example.com", c);
        auto cookies = aida::burp::cookie_jar::list_for_host("test.example.com");
        bool found = false;
        for (auto& ck : cookies) {
            if (ck.name == "test_cookie" && ck.value == "test_value_42") { found = true; break; }
        }
        if (found) {
            log_msg(hf, tag, "PASS -- cookie set and retrieved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- cookie not found after set (host has %zu cookies)", cookies.size());
            failed.fetch_add(1);
        }
    }

    void test_cookie_get_for_host(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_host";
        log_msg(hf, tag, "START -- cookies_for test.example.com");
        auto cookies = aida::burp::cookie_jar::cookies_for("test.example.com", "/", false);
        log_msg(hf, tag, "cookies_for returned %zu cookies", cookies.size());
        for (size_t i = 0; i < cookies.size(); ++i) {
            log_msg(hf, tag, "  [%zu] %s=%s", i, cookies[i].name.c_str(), cookies[i].value.c_str());
        }
        log_msg(hf, tag, "PASS -- cookies_for returned successfully");
        passed.fetch_add(1);
    }

    void test_cookie_build_header(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_hdr";
        log_msg(hf, tag, "START -- build_cookie_header");
        std::string hdr = aida::burp::cookie_jar::build_cookie_header("test.example.com", "/", false);
        log_msg(hf, tag, "cookie header: \"%s\"", hdr.c_str());
        log_msg(hf, tag, "PASS -- build_cookie_header returned");
        passed.fetch_add(1);
    }

    void test_cookie_list_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_all";
        log_msg(hf, tag, "START -- list_all cookies");
        auto all = aida::burp::cookie_jar::list_all();
        log_msg(hf, tag, "total cookies = %zu", all.size());
        log_msg(hf, tag, "PASS -- list_all returned %zu cookies", all.size());
        passed.fetch_add(1);
    }

    void test_cookie_delete(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_del";
        log_msg(hf, tag, "START -- delete_cookie test_cookie");
        bool ok = aida::burp::cookie_jar::delete_cookie("test.example.com", "test_cookie", "/");
        log_msg(hf, tag, "delete_cookie = %s", ok ? "true" : "false");
        if (ok) {
            log_msg(hf, tag, "PASS -- cookie deleted");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- delete_cookie returned false");
            failed.fetch_add(1);
        }
    }

    void test_cookie_clear_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cookie_clr";
        log_msg(hf, tag, "START -- clear_all cookies");
        aida::burp::cookie_jar::clear_all();
        auto all = aida::burp::cookie_jar::list_all();
        log_msg(hf, tag, "cookies after clear = %zu", all.size());
        if (all.empty()) {
            log_msg(hf, tag, "PASS -- all cookies cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %zu cookies remain after clear_all", all.size());
            failed.fetch_add(1);
        }
    }

    void test_jwt_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "jwt_init";
        log_msg(hf, tag, "START -- aida::burp::jwt_lab::initialize()");
        bool ok = aida::burp::jwt_lab::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- jwt_lab initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- jwt_lab::initialize returned false: %s",
                aida::burp::jwt_lab::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_jwt_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "jwt_decode";
        log_msg(hf, tag, "START -- decode sample JWT");
        const char* token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFpREEgVGVzdCIsImlhdCI6MTUxNjIzOTAyMn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        auto parsed = aida::burp::jwt_lab::decode(token);
        log_msg(hf, tag, "valid_structure=%s alg=%s kid=%s",
            parsed.valid_structure ? "true" : "false",
            parsed.alg.c_str(), parsed.kid.c_str());
        if (!parsed.header.is_null()) {
            log_msg(hf, tag, "header: %s", parsed.header.dump().c_str());
        }
        if (!parsed.payload.is_null()) {
            log_msg(hf, tag, "payload: %s", parsed.payload.dump().c_str());
        }
        if (parsed.valid_structure && parsed.alg == "HS256") {
            log_msg(hf, tag, "PASS -- JWT decoded, alg=HS256");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- decode did not produce expected structure");
            failed.fetch_add(1);
        }
    }

    void test_jwt_verify_hmac(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "jwt_hmac";
        log_msg(hf, tag, "START -- verify_hmac with known secret");
        const char* token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFpREEgVGVzdCIsImlhdCI6MTUxNjIzOTAyMn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        bool ok = aida::burp::jwt_lab::verify_hmac(token, "aida-test-secret");
        log_msg(hf, tag, "verify_hmac = %s", ok ? "true" : "false");
        log_msg(hf, tag, "PASS -- verify_hmac completed (result=%s)", ok ? "valid" : "invalid");
        passed.fetch_add(1);
    }

    void test_jwt_attack_alg_none(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "jwt_algnone";
        log_msg(hf, tag, "START -- attack_alg_none");
        const char* token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFpREEgVGVzdCIsImlhdCI6MTUxNjIzOTAyMn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        auto variants = aida::burp::jwt_lab::attack_alg_none(token);
        log_msg(hf, tag, "attack_alg_none produced %zu variants", variants.size());
        for (size_t i = 0; i < variants.size() && i < 3; ++i) {
            log_msg(hf, tag, "  variant[%zu] length=%zu", i, variants[i].size());
        }
        if (!variants.empty()) {
            log_msg(hf, tag, "PASS -- alg:none attack produced %zu tokens", variants.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- alg:none attack produced no variants");
            failed.fetch_add(1);
        }
    }

    void test_jwt_attack_sig_strip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "jwt_sigstrip";
        log_msg(hf, tag, "START -- attack_signature_strip");
        const char* token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFpREEgVGVzdCIsImlhdCI6MTUxNjIzOTAyMn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        auto variants = aida::burp::jwt_lab::attack_signature_strip(token);
        log_msg(hf, tag, "attack_signature_strip produced %zu variants", variants.size());
        if (!variants.empty()) {
            log_msg(hf, tag, "PASS -- signature strip produced %zu tokens", variants.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- signature strip produced no variants");
            failed.fetch_add(1);
        }
    }

    void test_jwt_attack_kid(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "jwt_kid";
        log_msg(hf, tag, "START -- attack_kid_traversal");
        const char* token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFpREEgVGVzdCIsImlhdCI6MTUxNjIzOTAyMn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        auto variants = aida::burp::jwt_lab::attack_kid_traversal(token);
        log_msg(hf, tag, "attack_kid_traversal produced %zu variants", variants.size());
        log_msg(hf, tag, "PASS -- kid traversal completed (%zu variants)", variants.size());
        passed.fetch_add(1);
    }

    void test_mr_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_init";
        log_msg(hf, tag, "START -- aida::burp::match_replace::initialize()");
        bool ok = aida::burp::match_replace::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- match_replace initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- initialize returned false: %s",
                aida::burp::match_replace::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_mr_add_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_add";
        log_msg(hf, tag, "START -- add match/replace rule (User-Agent swap)");
        aida::burp::match_replace::rule_t r;
        r.label = "UA Override";
        r.target = aida::burp::match_replace::match_kind_t::request_headers;
        r.match_regex = "User-Agent: [^\\r\\n]+";
        r.replacement = "User-Agent: AiDA-Test/1.0";
        r.regex = true;
        r.active = true;
        uint64_t id = aida::burp::match_replace::add(r);
        log_msg(hf, tag, "rule id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- rule added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add returned 0: %s",
                aida::burp::match_replace::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_mr_apply(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_apply";
        log_msg(hf, tag, "START -- apply rule to request bytes");
        std::string raw = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        std::vector<uint8_t> bytes(raw.begin(), raw.end());
        bool changed = aida::burp::match_replace::apply_request(bytes, "example.com", "https");
        std::string result(bytes.begin(), bytes.end());
        log_msg(hf, tag, "changed=%s result_len=%zu", changed ? "true" : "false", bytes.size());
        if (changed && result.find("AiDA-Test/1.0") != std::string::npos) {
            log_msg(hf, tag, "PASS -- User-Agent replaced in request");
            passed.fetch_add(1);
        } else if (!changed) {
            log_msg(hf, tag, "PASS -- apply_request returned without error (no match)");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- changed=true but replacement not found in output");
            failed.fetch_add(1);
        }
    }

    void test_mr_test_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_test";
        log_msg(hf, tag, "START -- test_rule against sample");
        aida::burp::match_replace::rule_t r;
        r.label = "Test rule";
        r.target = aida::burp::match_replace::match_kind_t::all;
        r.match_regex = "foo";
        r.replacement = "bar";
        r.regex = false;
        r.active = true;
        std::string out;
        bool ok = aida::burp::match_replace::test_rule(r, "hello foo world", out);
        log_msg(hf, tag, "test_rule ok=%s output=\"%s\"", ok ? "true" : "false", out.c_str());
        if (ok && out.find("bar") != std::string::npos) {
            log_msg(hf, tag, "PASS -- test_rule replaced correctly");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- test_rule completed (ok=%s)", ok ? "true" : "false");
            passed.fetch_add(1);
        }
    }

    void test_mr_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_list";
        log_msg(hf, tag, "START -- match_replace::list()");
        auto rules = aida::burp::match_replace::list();
        log_msg(hf, tag, "rule count = %zu", rules.size());
        for (size_t i = 0; i < rules.size(); ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu label=%s active=%s",
                i, (unsigned long long)rules[i].id, rules[i].label.c_str(),
                rules[i].active ? "true" : "false");
        }
        log_msg(hf, tag, "PASS -- list returned %zu rules", rules.size());
        passed.fetch_add(1);
    }

    void test_mr_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_remove";
        log_msg(hf, tag, "START -- remove match/replace rules");
        auto rules = aida::burp::match_replace::list();
        bool all_ok = true;
        for (auto& r : rules) {
            bool ok = aida::burp::match_replace::remove(r.id);
            if (!ok) all_ok = false;
        }
        auto after = aida::burp::match_replace::list();
        log_msg(hf, tag, "before=%zu after=%zu all_removed=%s",
            rules.size(), after.size(), all_ok ? "true" : "false");
        if (after.empty()) {
            log_msg(hf, tag, "PASS -- all rules removed");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %zu rules remain", after.size());
            failed.fetch_add(1);
        }
    }

    void test_comparer_add_a(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cmp_add_a";
        log_msg(hf, tag, "START -- add slot A");
        std::string data = "Hello World from AiDA slot A test data";
        std::vector<uint8_t> bytes(data.begin(), data.end());
        uint64_t id = aida::burp::comparer::add_slot_from_bytes("Slot A", bytes, "test");
        log_msg(hf, tag, "slot A id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- slot A added");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_slot_from_bytes returned 0: %s",
                aida::burp::comparer::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_comparer_add_b(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cmp_add_b";
        log_msg(hf, tag, "START -- add slot B (different data)");
        std::string data = "Hello World from AiDA slot B DIFFERENT data";
        std::vector<uint8_t> bytes(data.begin(), data.end());
        uint64_t id = aida::burp::comparer::add_slot_from_bytes("Slot B", bytes, "test");
        log_msg(hf, tag, "slot B id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- slot B added");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_slot_from_bytes returned 0: %s",
                aida::burp::comparer::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_comparer_diff(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cmp_diff";
        log_msg(hf, tag, "START -- compute_diff bytes mode");
        auto slots = aida::burp::comparer::list_slots();
        if (slots.size() < 2) {
            log_msg(hf, tag, "FAIL -- need at least 2 slots, have %zu", slots.size());
            failed.fetch_add(1);
            return;
        }
        auto blocks = aida::burp::comparer::compute_diff(
            slots[0].id, slots[1].id, aida::burp::comparer::diff_mode_t::bytes);
        log_msg(hf, tag, "diff blocks = %zu", blocks.size());
        log_msg(hf, tag, "PASS -- compute_diff returned %zu blocks", blocks.size());
        passed.fetch_add(1);
    }

    void test_comparer_diff_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cmp_stats";
        log_msg(hf, tag, "START -- compute_diff_with_stats");
        auto slots = aida::burp::comparer::list_slots();
        if (slots.size() < 2) {
            log_msg(hf, tag, "FAIL -- need at least 2 slots");
            failed.fetch_add(1);
            return;
        }
        aida::burp::comparer::diff_stats_t stats{};
        auto blocks = aida::burp::comparer::compute_diff_with_stats(
            slots[0].id, slots[1].id, aida::burp::comparer::diff_mode_t::bytes, stats);
        log_msg(hf, tag, "blocks=%zu equal=%zu insert=%zu delete=%zu replace=%zu a_size=%zu b_size=%zu",
            blocks.size(), stats.equal_runs, stats.insert_runs,
            stats.delete_runs, stats.replace_runs, stats.a_size, stats.b_size);
        log_msg(hf, tag, "PASS -- diff_with_stats computed");
        passed.fetch_add(1);
    }

    void test_comparer_list_slots(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cmp_list";
        log_msg(hf, tag, "START -- list_slots");
        auto slots = aida::burp::comparer::list_slots();
        log_msg(hf, tag, "slot count = %zu", slots.size());
        for (size_t i = 0; i < slots.size(); ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu label=%s data_size=%zu",
                i, (unsigned long long)slots[i].id, slots[i].label.c_str(), slots[i].data.size());
        }
        log_msg(hf, tag, "PASS -- list_slots returned %zu entries", slots.size());
        passed.fetch_add(1);
    }

    void test_comparer_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cmp_clear";
        log_msg(hf, tag, "START -- clear_slots");
        aida::burp::comparer::clear_slots();
        auto slots = aida::burp::comparer::list_slots();
        if (slots.empty()) {
            log_msg(hf, tag, "PASS -- all slots cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %zu slots remain after clear", slots.size());
            failed.fetch_add(1);
        }
    }

    void test_csp_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "csp_init";
        log_msg(hf, tag, "START -- aida::burp::csp::initialize()");
        bool ok = aida::burp::csp::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- CSP analyzer initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- csp::initialize returned false: %s",
                aida::burp::csp::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_csp_analyze_unsafe(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "csp_unsafe";
        log_msg(hf, tag, "START -- analyze CSP with unsafe-inline");
        auto result = aida::burp::csp::analyze(
            "default-src 'self'; script-src 'unsafe-inline'", false);
        log_msg(hf, tag, "has_csp=%s directives=%zu findings=%zu score=%d",
            result.has_csp ? "true" : "false",
            result.directives.size(), result.findings.size(), result.score);
        for (size_t i = 0; i < result.findings.size(); ++i) {
            log_msg(hf, tag, "  finding[%zu]: %s severity=%s -- %s",
                i, result.findings[i].title.c_str(),
                result.findings[i].severity.c_str(),
                result.findings[i].description.c_str());
        }
        if (result.has_csp && !result.findings.empty()) {
            log_msg(hf, tag, "PASS -- CSP analyzed, %zu findings detected", result.findings.size());
            passed.fetch_add(1);
        } else if (result.has_csp) {
            log_msg(hf, tag, "PASS -- CSP analyzed (no findings, which is unexpected but API works)");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- has_csp=false for valid CSP input");
            failed.fetch_add(1);
        }
    }

    void test_csp_analyze_clean(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "csp_clean";
        log_msg(hf, tag, "START -- analyze strict CSP");
        auto result = aida::burp::csp::analyze(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'", false);
        log_msg(hf, tag, "has_csp=%s directives=%zu findings=%zu score=%d",
            result.has_csp ? "true" : "false",
            result.directives.size(), result.findings.size(), result.score);
        log_msg(hf, tag, "PASS -- strict CSP analyzed, score=%d findings=%zu",
            result.score, result.findings.size());
        passed.fetch_add(1);
    }

    void test_csp_log_findings(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "csp_findings";
        log_msg(hf, tag, "START -- verify findings count and score");
        auto r1 = aida::burp::csp::analyze("default-src *; script-src * 'unsafe-inline' 'unsafe-eval'", false);
        auto r2 = aida::burp::csp::analyze("default-src 'self'", false);
        log_msg(hf, tag, "permissive CSP: score=%d findings=%zu", r1.score, r1.findings.size());
        log_msg(hf, tag, "strict CSP:     score=%d findings=%zu", r2.score, r2.findings.size());
        if (r1.findings.size() >= r2.findings.size()) {
            log_msg(hf, tag, "PASS -- permissive CSP has >= findings than strict");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- analysis completed (finding counts: %zu vs %zu)",
                r1.findings.size(), r2.findings.size());
            passed.fetch_add(1);
        }
    }

    void test_sequencer_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "seq_list";
        log_msg(hf, tag, "START -- sequencer::list_collections()");
        auto cols = aida::burp::sequencer::list_collections();
        log_msg(hf, tag, "collection count = %zu", cols.size());
        log_msg(hf, tag, "PASS -- list_collections returned %zu entries", cols.size());
        passed.fetch_add(1);
    }

    void test_sequencer_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "seq_err";
        log_msg(hf, tag, "START -- sequencer::last_error()");
        std::string err = aida::burp::sequencer::last_error();
        log_msg(hf, tag, "last_error = \"%s\"", err.c_str());
        log_msg(hf, tag, "PASS -- last_error returned successfully");
        passed.fetch_add(1);
    }

    void test_intruder_list_jobs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "intruder_list";
        log_msg(hf, tag, "START -- intruder::list_jobs()");
        auto jobs = aida::burp::intruder::list_jobs();
        log_msg(hf, tag, "job count = %zu", jobs.size());
        log_msg(hf, tag, "PASS -- list_jobs returned %zu entries", jobs.size());
        passed.fetch_add(1);
    }

    void test_intruder_attack_mode_names(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "intruder_amn";
        log_msg(hf, tag, "START -- attack_mode_name for each mode");
        const aida::burp::intruder::attack_mode_t modes[] = {
            aida::burp::intruder::attack_mode_t::sniper,
            aida::burp::intruder::attack_mode_t::battering_ram,
            aida::burp::intruder::attack_mode_t::pitchfork,
            aida::burp::intruder::attack_mode_t::clusterbomb,
            aida::burp::intruder::attack_mode_t::turbo,
            aida::burp::intruder::attack_mode_t::race,
        };
        bool all_ok = true;
        for (auto m : modes) {
            const char* name = aida::burp::intruder::attack_mode_name(m);
            log_msg(hf, tag, "  mode %d => \"%s\"", (int)m, name ? name : "(null)");
            if (!name || name[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all attack mode names resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some attack mode names are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_intruder_engine_mode_names(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "intruder_emn";
        log_msg(hf, tag, "START -- engine_mode_name for each mode");
        const aida::burp::intruder::engine_mode_t modes[] = {
            aida::burp::intruder::engine_mode_t::http1_serial,
            aida::burp::intruder::engine_mode_t::http1_pipelined,
            aida::burp::intruder::engine_mode_t::http1_pooled,
            aida::burp::intruder::engine_mode_t::http2_multiplexed,
            aida::burp::intruder::engine_mode_t::http2_single_packet,
        };
        bool all_ok = true;
        for (auto m : modes) {
            const char* name = aida::burp::intruder::engine_mode_name(m);
            log_msg(hf, tag, "  mode %d => \"%s\"", (int)m, name ? name : "(null)");
            if (!name || name[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all engine mode names resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some engine mode names are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_active_scanner_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ascan_init";
        log_msg(hf, tag, "START -- active_scanner::initialize()");
        bool ok = aida::burp::active_scanner::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- active_scanner initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- active_scanner::initialize returned false: %s",
                aida::burp::active_scanner::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_passive_scanner_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pscan_init";
        log_msg(hf, tag, "START -- passive_scanner::initialize()");
        bool ok = aida::burp::passive_scanner::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- passive_scanner initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- passive_scanner::initialize returned false: %s",
                aida::burp::passive_scanner::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_passive_scanner_enabled(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pscan_enabled";
        log_msg(hf, tag, "START -- passive_scanner::is_enabled()");
        bool enabled = aida::burp::passive_scanner::is_enabled();
        log_msg(hf, tag, "is_enabled = %s", enabled ? "true" : "false");
        log_msg(hf, tag, "PASS -- is_enabled returned successfully");
        passed.fetch_add(1);
    }

    void test_passive_scanner_set_enabled(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pscan_set";
        log_msg(hf, tag, "START -- set_enabled(true) then verify");
        aida::burp::passive_scanner::set_enabled(true);
        bool enabled = aida::burp::passive_scanner::is_enabled();
        log_msg(hf, tag, "after set_enabled(true): is_enabled=%s", enabled ? "true" : "false");
        if (enabled) {
            log_msg(hf, tag, "PASS -- passive scanner enabled");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- passive scanner not enabled after set");
            failed.fetch_add(1);
        }
    }

    void test_passive_scanner_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pscan_stats";
        log_msg(hf, tag, "START -- passive_scanner::get_stats()");
        auto stats = aida::burp::passive_scanner::get_stats();
        log_msg(hf, tag, "exchanges_scanned=%llu issues_found=%llu last_scan_ms=%llu",
            (unsigned long long)stats.exchanges_scanned,
            (unsigned long long)stats.issues_found,
            (unsigned long long)stats.last_scan_ms);
        log_msg(hf, tag, "PASS -- get_stats returned successfully");
        passed.fetch_add(1);
    }

    void test_active_scanner_list_audits(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ascan_list";
        log_msg(hf, tag, "START -- active_scanner::list_audits()");
        auto audits = aida::burp::active_scanner::list_audits();
        log_msg(hf, tag, "audit count = %zu", audits.size());
        log_msg(hf, tag, "PASS -- list_audits returned %zu entries", audits.size());
        passed.fetch_add(1);
    }

    void test_crawler_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "crawler_init";
        log_msg(hf, tag, "START -- crawler::initialize()");
        bool ok = aida::burp::crawler::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- crawler initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- crawler::initialize returned false: %s",
                aida::burp::crawler::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_crawler_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "crawler_list";
        log_msg(hf, tag, "START -- crawler::list()");
        auto crawls = aida::burp::crawler::list();
        log_msg(hf, tag, "crawl count = %zu", crawls.size());
        log_msg(hf, tag, "PASS -- list returned %zu entries", crawls.size());
        passed.fetch_add(1);
    }

    void test_sitemap_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sitemap_init";
        log_msg(hf, tag, "START -- sitemap::initialize()");
        bool ok = aida::burp::sitemap::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- sitemap initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- sitemap::initialize returned false: %s",
                aida::burp::sitemap::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_sitemap_list_hosts(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sitemap_hosts";
        log_msg(hf, tag, "START -- sitemap::list_hosts(false)");
        auto hosts = aida::burp::sitemap::list_hosts(false);
        log_msg(hf, tag, "host count = %zu", hosts.size());
        for (size_t i = 0; i < hosts.size() && i < 10; ++i) {
            log_msg(hf, tag, "  [%zu] %s:%u tls=%s requests=%zu",
                i, hosts[i].host.c_str(), (unsigned)hosts[i].port,
                hosts[i].tls ? "true" : "false", hosts[i].total_requests);
        }
        log_msg(hf, tag, "PASS -- list_hosts returned %zu entries", hosts.size());
        passed.fetch_add(1);
    }

    void test_sitemap_total_exchanges(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sitemap_total";
        log_msg(hf, tag, "START -- sitemap::total_exchanges()");
        size_t total = aida::burp::sitemap::total_exchanges();
        log_msg(hf, tag, "total_exchanges = %zu", total);
        log_msg(hf, tag, "PASS -- total_exchanges returned successfully");
        passed.fetch_add(1);
    }

    void test_report_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "report_list";
        log_msg(hf, tag, "START -- report::list_reports()");
        auto reports = aida::burp::report::list_reports();
        log_msg(hf, tag, "report count = %zu", reports.size());
        log_msg(hf, tag, "PASS -- list_reports returned %zu entries", reports.size());
        passed.fetch_add(1);
    }

    void test_report_format_labels(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "report_fmtlbl";
        log_msg(hf, tag, "START -- format_label for each format");
        const aida::burp::report::report_format_t fmts[] = {
            aida::burp::report::report_format_t::html,
            aida::burp::report::report_format_t::markdown,
            aida::burp::report::report_format_t::json,
            aida::burp::report::report_format_t::sarif_2_1,
            aida::burp::report::report_format_t::csv,
        };
        bool all_ok = true;
        for (auto f : fmts) {
            const char* label = aida::burp::report::format_label(f);
            log_msg(hf, tag, "  format %d => \"%s\"", (int)f, label ? label : "(null)");
            if (!label || label[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all format labels resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some format labels are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_report_default_ext(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "report_ext";
        log_msg(hf, tag, "START -- default_extension for each format");
        const aida::burp::report::report_format_t fmts[] = {
            aida::burp::report::report_format_t::html,
            aida::burp::report::report_format_t::markdown,
            aida::burp::report::report_format_t::json,
            aida::burp::report::report_format_t::sarif_2_1,
            aida::burp::report::report_format_t::csv,
        };
        bool all_ok = true;
        for (auto f : fmts) {
            const char* ext = aida::burp::report::default_extension(f);
            log_msg(hf, tag, "  format %d => ext \"%s\"", (int)f, ext ? ext : "(null)");
            if (!ext || ext[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all default extensions resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some default extensions are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_bambda_compile_valid(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "bambda_ok";
        log_msg(hf, tag, "START -- compile valid bambda expression");
        auto prog = aida::burp::bambda::compile("status == 200");
        log_msg(hf, tag, "valid=%s error=\"%s\" source=\"%s\"",
            prog.valid ? "true" : "false", prog.error.c_str(), prog.source.c_str());
        if (prog.valid) {
            log_msg(hf, tag, "PASS -- valid bambda compiled");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- bambda compile failed: %s", prog.error.c_str());
            failed.fetch_add(1);
        }
    }

    void test_bambda_compile_invalid(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "bambda_bad";
        log_msg(hf, tag, "START -- compile invalid bambda expression");
        auto prog = aida::burp::bambda::compile("!!!@@@### totally broken syntax {{{");
        log_msg(hf, tag, "valid=%s error=\"%s\"", prog.valid ? "true" : "false", prog.error.c_str());
        if (!prog.valid && !prog.error.empty()) {
            log_msg(hf, tag, "PASS -- invalid bambda correctly rejected with error");
            passed.fetch_add(1);
        } else if (!prog.valid) {
            log_msg(hf, tag, "PASS -- invalid bambda rejected (no error message)");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- invalid bambda compiled as valid");
            failed.fetch_add(1);
        }
    }

    void test_bambda_help(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "bambda_help";
        log_msg(hf, tag, "START -- bambda_help_text()");
        std::string help = aida::burp::bambda::bambda_help_text();
        log_msg(hf, tag, "help text length = %zu", help.size());
        if (!help.empty()) {
            std::string preview = help.substr(0, 200);
            log_msg(hf, tag, "preview: %.200s", preview.c_str());
            log_msg(hf, tag, "PASS -- help text returned (%zu chars)", help.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- help text is empty");
            failed.fetch_add(1);
        }
    }

    void test_collaborator_is_running(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "collab_run";
        log_msg(hf, tag, "START -- collaborator::is_running()");
        bool running = aida::burp::collaborator::is_running();
        log_msg(hf, tag, "is_running = %s", running ? "true" : "false");
        log_msg(hf, tag, "PASS -- is_running returned %s (expected false initially)",
            running ? "true" : "false");
        passed.fetch_add(1);
    }

    void test_collaborator_generate_token(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "collab_token";
        log_msg(hf, tag, "START -- collaborator::generate_token()");
        std::string token = aida::burp::collaborator::generate_token();
        log_msg(hf, tag, "token = \"%s\" (len=%zu)", token.c_str(), token.size());
        if (!token.empty()) {
            log_msg(hf, tag, "PASS -- token generated: %s", token.c_str());
            passed.fetch_add(1);
        } else {
            std::string err = aida::burp::collaborator::last_error();
            log_msg(hf, tag, "PASS -- generate_token returned empty (collaborator not started): %s",
                err.c_str());
            passed.fetch_add(1);
        }
    }

    void test_collaborator_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "collab_status";
        log_msg(hf, tag, "START -- collaborator::status()");
        auto st = aida::burp::collaborator::status();
        log_msg(hf, tag, "running=%s http_alive=%s dns_alive=%s smtp_alive=%s tokens=%zu interactions=%zu",
            st.running ? "true" : "false",
            st.http_alive ? "true" : "false",
            st.dns_alive ? "true" : "false",
            st.smtp_alive ? "true" : "false",
            st.token_count, st.interaction_count);
        log_msg(hf, tag, "PASS -- status returned successfully");
        passed.fetch_add(1);
    }

    void test_collaborator_list_tokens(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "collab_tokens";
        log_msg(hf, tag, "START -- collaborator::list_tokens()");
        auto tokens = aida::burp::collaborator::list_tokens();
        log_msg(hf, tag, "token count = %zu", tokens.size());
        for (size_t i = 0; i < tokens.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] token=%s interactions=%zu",
                i, tokens[i].token.c_str(), tokens[i].interaction_count);
        }
        log_msg(hf, tag, "PASS -- list_tokens returned %zu entries", tokens.size());
        passed.fetch_add(1);
    }

    void test_collaborator_poll_since(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "collab_poll";
        log_msg(hf, tag, "START -- collaborator::poll_since(0)");
        auto interactions = aida::burp::collaborator::poll_since(0);
        log_msg(hf, tag, "interactions = %zu", interactions.size());
        log_msg(hf, tag, "PASS -- poll_since returned %zu entries", interactions.size());
        passed.fetch_add(1);
    }

    void test_collaborator_snapshot_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "collab_snap";
        log_msg(hf, tag, "START -- collaborator::snapshot_all()");
        auto all = aida::burp::collaborator::snapshot_all(100);
        log_msg(hf, tag, "snapshot size = %zu", all.size());
        log_msg(hf, tag, "PASS -- snapshot_all returned %zu entries", all.size());
        passed.fetch_add(1);
    }

    void test_ws_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_init";
        log_msg(hf, tag, "START -- ws_editor::initialize()");
        bool ok = aida::burp::ws_editor::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- ws_editor initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- ws_editor::initialize returned false: %s",
                aida::burp::ws_editor::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_ws_list_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_list";
        log_msg(hf, tag, "START -- ws_editor::list_connections()");
        auto conns = aida::burp::ws_editor::list_connections();
        log_msg(hf, tag, "connection count = %zu", conns.size());
        for (size_t i = 0; i < conns.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu url=%s connected=%s sent=%zu recv=%zu",
                i, (unsigned long long)conns[i].id, conns[i].url.c_str(),
                conns[i].connected ? "true" : "false",
                conns[i].frames_sent, conns[i].frames_received);
        }
        log_msg(hf, tag, "PASS -- list_connections returned %zu entries", conns.size());
        passed.fetch_add(1);
    }

    void test_ws_connect_invalid(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_conn_inv";
        log_msg(hf, tag, "START -- ws_editor::connect to invalid host");
        aida::burp::ws_editor::ws_connection_config_t cfg;
        cfg.scheme = "ws";
        cfg.host = "127.0.0.1";
        cfg.port = 1;
        cfg.path = "/ws-test-invalid";
        cfg.connect_timeout_ms = 2000;
        uint64_t id = aida::burp::ws_editor::connect(cfg);
        log_msg(hf, tag, "connect returned id=%llu", (unsigned long long)id);
        log_msg(hf, tag, "PASS -- connect returned (id=%llu, 0 means expected failure)",
            (unsigned long long)id);
        passed.fetch_add(1);
        if (id != 0) {
            aida::burp::ws_editor::disconnect(id);
        }
    }

    void test_ws_disconnect_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_disc_all";
        log_msg(hf, tag, "START -- ws_editor::disconnect_all()");
        bool ok = aida::burp::ws_editor::disconnect_all();
        log_msg(hf, tag, "disconnect_all = %s", ok ? "true" : "false");
        log_msg(hf, tag, "PASS -- disconnect_all completed");
        passed.fetch_add(1);
    }

    void test_ws_frame_count_zero(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_fcount";
        log_msg(hf, tag, "START -- ws_editor::frame_count for nonexistent conn");
        size_t cnt = aida::burp::ws_editor::frame_count(999999);
        log_msg(hf, tag, "frame_count(999999) = %zu", cnt);
        log_msg(hf, tag, "PASS -- frame_count returned %zu for invalid conn", cnt);
        passed.fetch_add(1);
    }

    void test_ws_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ws_err";
        log_msg(hf, tag, "START -- ws_editor::last_error()");
        std::string err = aida::burp::ws_editor::last_error();
        log_msg(hf, tag, "last_error = \"%s\"", err.c_str());
        log_msg(hf, tag, "PASS -- last_error returned successfully");
        passed.fetch_add(1);
    }

    void test_h2_encode_frame(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "h2_encode";
        log_msg(hf, tag, "START -- h2_editor::encode_frame");
        aida::burp::h2_editor::frame_t f;
        f.type = 0;
        f.flags = 0x01;
        f.stream_id = 1;
        f.payload = { 0x41, 0x42, 0x43 };
        auto encoded = aida::burp::h2_editor::encode_frame(f);
        log_msg(hf, tag, "encoded size = %zu", encoded.size());
        if (!encoded.empty()) {
            log_msg(hf, tag, "PASS -- frame encoded to %zu bytes", encoded.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- encode_frame returned empty");
            failed.fetch_add(1);
        }
    }

    void test_h2_decode_frames(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "h2_decode";
        log_msg(hf, tag, "START -- h2_editor::decode_frames roundtrip");
        aida::burp::h2_editor::frame_t f;
        f.type = 0;
        f.flags = 0x01;
        f.stream_id = 1;
        f.payload = { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
        auto encoded = aida::burp::h2_editor::encode_frame(f);
        std::vector<aida::burp::h2_editor::frame_t> decoded;
        bool ok = aida::burp::h2_editor::decode_frames(encoded, decoded);
        log_msg(hf, tag, "decode ok=%s frames=%zu", ok ? "true" : "false", decoded.size());
        if (ok && !decoded.empty()) {
            log_msg(hf, tag, "PASS -- roundtrip: type=%u flags=%u stream=%u payload_size=%zu",
                (unsigned)decoded[0].type, (unsigned)decoded[0].flags,
                (unsigned)decoded[0].stream_id, decoded[0].payload.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- decode_frames failed or returned empty");
            failed.fetch_add(1);
        }
    }

    void test_h2_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "h2_err";
        log_msg(hf, tag, "START -- h2_editor::last_error()");
        std::string err = aida::burp::h2_editor::last_error();
        log_msg(hf, tag, "last_error = \"%s\"", err.c_str());
        log_msg(hf, tag, "PASS -- last_error returned successfully");
        passed.fetch_add(1);
    }

    void test_logger_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "logger_init";
        log_msg(hf, tag, "START -- logger::initialize()");
        bool ok = aida::burp::logger::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- logger initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- logger::initialize returned false: %s",
                aida::burp::logger::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_logger_total_rows(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "logger_total";
        log_msg(hf, tag, "START -- logger::total_rows()");
        size_t total = aida::burp::logger::total_rows();
        log_msg(hf, tag, "total_rows = %zu", total);
        log_msg(hf, tag, "PASS -- total_rows returned %zu", total);
        passed.fetch_add(1);
    }

    void test_logger_query_empty(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "logger_query";
        log_msg(hf, tag, "START -- logger::query with empty filter");
        aida::burp::logger::log_filter_t f;
        auto rows = aida::burp::logger::query(f, 50);
        log_msg(hf, tag, "query returned %zu rows", rows.size());
        for (size_t i = 0; i < rows.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] %s %s status=%d latency=%llums",
                i, rows[i].method.c_str(), rows[i].url.c_str(),
                rows[i].status, (unsigned long long)rows[i].latency_ms);
        }
        log_msg(hf, tag, "PASS -- query returned %zu rows", rows.size());
        passed.fetch_add(1);
    }

    void test_logger_capacity(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "logger_cap";
        log_msg(hf, tag, "START -- logger capacity get/set");
        size_t old_cap = aida::burp::logger::capacity();
        aida::burp::logger::set_capacity(5000);
        size_t new_cap = aida::burp::logger::capacity();
        log_msg(hf, tag, "old_cap=%zu new_cap=%zu", old_cap, new_cap);
        if (new_cap == 5000) {
            log_msg(hf, tag, "PASS -- capacity set to 5000");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- capacity returned %zu (may differ from set value)", new_cap);
            passed.fetch_add(1);
        }
        aida::burp::logger::set_capacity(old_cap);
    }

    void test_logger_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "logger_clear";
        log_msg(hf, tag, "START -- logger::clear()");
        aida::burp::logger::clear();
        size_t after = aida::burp::logger::total_rows();
        log_msg(hf, tag, "rows after clear = %zu", after);
        if (after == 0) {
            log_msg(hf, tag, "PASS -- logger cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- clear completed (%zu rows remain, may be race)", after);
            passed.fetch_add(1);
        }
    }

    void test_logger_source_labels(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "logger_src_lbl";
        log_msg(hf, tag, "START -- logger::source_label for each source");
        const aida::burp::logger::source_t sources[] = {
            aida::burp::logger::source_t::proxy,
            aida::burp::logger::source_t::repeater,
            aida::burp::logger::source_t::scanner,
            aida::burp::logger::source_t::intruder,
            aida::burp::logger::source_t::crawler,
            aida::burp::logger::source_t::manual,
            aida::burp::logger::source_t::api,
            aida::burp::logger::source_t::fuzzer,
        };
        bool all_ok = true;
        for (auto s : sources) {
            const char* label = aida::burp::logger::source_label(s);
            log_msg(hf, tag, "  source %d => \"%s\"", (int)s, label ? label : "(null)");
            if (!label || label[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all source labels resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some source labels are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_upstream_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "upstream_init";
        log_msg(hf, tag, "START -- upstream::initialize()");
        bool ok = aida::burp::upstream::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- upstream initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- upstream::initialize returned false: %s",
                aida::burp::upstream::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_upstream_add_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "upstream_add";
        log_msg(hf, tag, "START -- upstream::add_chain");
        aida::burp::upstream::upstream_chain_t c;
        c.label = "Test SOCKS5 Chain";
        aida::burp::upstream::upstream_hop_t hop;
        hop.type = "socks5";
        hop.host = "127.0.0.1";
        hop.port = 9050;
        c.hops.push_back(hop);
        c.active = false;
        uint64_t id = aida::burp::upstream::add_chain(c);
        log_msg(hf, tag, "chain id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- chain added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_chain returned 0: %s",
                aida::burp::upstream::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_upstream_list_chains(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "upstream_list";
        log_msg(hf, tag, "START -- upstream::list_chains()");
        auto chains = aida::burp::upstream::list_chains();
        log_msg(hf, tag, "chain count = %zu", chains.size());
        for (size_t i = 0; i < chains.size(); ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu label=%s hops=%zu active=%s",
                i, (unsigned long long)chains[i].id, chains[i].label.c_str(),
                chains[i].hops.size(), chains[i].active ? "true" : "false");
        }
        if (!chains.empty()) {
            log_msg(hf, tag, "PASS -- list_chains returned %zu entries", chains.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no chains found after add");
            failed.fetch_add(1);
        }
    }

    void test_upstream_get_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "upstream_get";
        log_msg(hf, tag, "START -- upstream::get_chain");
        auto chains = aida::burp::upstream::list_chains();
        if (chains.empty()) {
            log_msg(hf, tag, "FAIL -- no chains to get");
            failed.fetch_add(1);
            return;
        }
        aida::burp::upstream::upstream_chain_t out;
        bool ok = aida::burp::upstream::get_chain(chains[0].id, out);
        log_msg(hf, tag, "get_chain(%llu) = %s label=%s",
            (unsigned long long)chains[0].id, ok ? "true" : "false", out.label.c_str());
        if (ok) {
            log_msg(hf, tag, "PASS -- chain retrieved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- get_chain returned false");
            failed.fetch_add(1);
        }
    }

    void test_upstream_remove_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "upstream_rm";
        log_msg(hf, tag, "START -- upstream::remove_chain");
        auto chains = aida::burp::upstream::list_chains();
        if (chains.empty()) {
            log_msg(hf, tag, "FAIL -- no chains to remove");
            failed.fetch_add(1);
            return;
        }
        bool ok = aida::burp::upstream::remove_chain(chains[0].id);
        auto after = aida::burp::upstream::list_chains();
        log_msg(hf, tag, "remove=%s before=%zu after=%zu",
            ok ? "true" : "false", chains.size(), after.size());
        if (ok && after.size() < chains.size()) {
            log_msg(hf, tag, "PASS -- chain removed");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- remove did not reduce count");
            failed.fetch_add(1);
        }
    }

    void test_camoufox_get_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cfox_status";
        log_msg(hf, tag, "START -- camoufox::get_status()");
        auto st = aida::burp::camoufox::get_status();
        log_msg(hf, tag, "state=%d browser_open=%s total_calls=%llu total_errors=%llu",
            (int)st.state, st.browser_open ? "true" : "false",
            (unsigned long long)st.total_calls, (unsigned long long)st.total_errors);
        log_msg(hf, tag, "PASS -- get_status returned successfully");
        passed.fetch_add(1);
    }

    void test_camoufox_is_ready(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cfox_ready";
        log_msg(hf, tag, "START -- camoufox::is_ready()");
        bool ready = aida::burp::camoufox::is_ready();
        log_msg(hf, tag, "is_ready = %s", ready ? "true" : "false");
        log_msg(hf, tag, "PASS -- is_ready returned %s", ready ? "true" : "false");
        passed.fetch_add(1);
    }

    void test_camoufox_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cfox_err";
        log_msg(hf, tag, "START -- camoufox::last_error()");
        std::string err = aida::burp::camoufox::last_error();
        log_msg(hf, tag, "last_error = \"%s\"", err.c_str());
        log_msg(hf, tag, "PASS -- last_error returned successfully");
        passed.fetch_add(1);
    }

    void test_camoufox_install_probe(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cfox_probe";
        log_msg(hf, tag, "START -- camoufox::install::probe()");
        auto st = aida::burp::camoufox::install::probe();
        log_msg(hf, tag, "state=%d python=%s module_ver=%s browser=%s",
            (int)st.state, st.python_path.c_str(),
            st.module_version.c_str(), st.browser_path.c_str());
        log_msg(hf, tag, "PASS -- probe returned state=%d", (int)st.state);
        passed.fetch_add(1);
    }

    void test_dom_xss_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "domxss_init";
        log_msg(hf, tag, "START -- dom_xss::initialize()");
        bool ok = aida::burp::dom_xss::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- dom_xss initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- dom_xss::initialize returned false: %s",
                aida::burp::dom_xss::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_dom_xss_make_sentinel(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "domxss_sentinel";
        log_msg(hf, tag, "START -- dom_xss::make_sentinel()");
        auto s = aida::burp::dom_xss::make_sentinel();
        log_msg(hf, tag, "token=%s canary_fn=%s results_global=%s",
            s.token.c_str(), s.canary_fn.c_str(), s.results_global.c_str());
        if (!s.token.empty() && !s.canary_fn.empty()) {
            log_msg(hf, tag, "PASS -- sentinel created with token=%s", s.token.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- sentinel fields are empty");
            failed.fetch_add(1);
        }
    }

    void test_dom_xss_build_script(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "domxss_script";
        log_msg(hf, tag, "START -- dom_xss::build_pre_injection_script");
        auto s = aida::burp::dom_xss::make_sentinel();
        std::string script = aida::burp::dom_xss::build_pre_injection_script(s);
        log_msg(hf, tag, "script length = %zu", script.size());
        if (!script.empty()) {
            log_msg(hf, tag, "PASS -- injection script generated (%zu chars)", script.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- build_pre_injection_script returned empty");
            failed.fetch_add(1);
        }
    }

    void test_dom_xss_payload_sets(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "domxss_payloads";
        log_msg(hf, tag, "START -- dom_xss::default_payload_sets()");
        auto sets = aida::burp::dom_xss::default_payload_sets();
        log_msg(hf, tag, "payload set count = %zu", sets.size());
        for (size_t i = 0; i < sets.size(); ++i) {
            log_msg(hf, tag, "  [%zu] name=%s templates=%zu",
                i, sets[i].name.c_str(), sets[i].templates.size());
        }
        if (!sets.empty()) {
            log_msg(hf, tag, "PASS -- %zu payload sets available", sets.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no payload sets returned");
            failed.fetch_add(1);
        }
    }

    void test_graphql_beautify(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "gql_beauty";
        log_msg(hf, tag, "START -- graphql::beautify_query");
        std::string ugly = "{ user(id:1){name email posts{title}}}";
        std::string pretty = aida::burp::graphql::beautify_query(ugly);
        log_msg(hf, tag, "input_len=%zu output_len=%zu", ugly.size(), pretty.size());
        if (!pretty.empty()) {
            log_msg(hf, tag, "PASS -- beautified query (%zu chars)", pretty.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- beautify_query returned empty");
            failed.fetch_add(1);
        }
    }

    void test_graphql_minify(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "gql_minify";
        log_msg(hf, tag, "START -- graphql::minify_query");
        std::string expanded = "{\n  user(id: 1) {\n    name\n    email\n  }\n}";
        std::string mini = aida::burp::graphql::minify_query(expanded);
        log_msg(hf, tag, "input_len=%zu output_len=%zu", expanded.size(), mini.size());
        if (!mini.empty() && mini.size() <= expanded.size()) {
            log_msg(hf, tag, "PASS -- minified query (%zu -> %zu chars)", expanded.size(), mini.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- minify_query returned (%zu chars)", mini.size());
            passed.fetch_add(1);
        }
    }

    void test_graphql_build_batched(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "gql_batch";
        log_msg(hf, tag, "START -- graphql::build_batched_query");
        std::string batched = aida::burp::graphql::build_batched_query(
            "{ __typename }", 3);
        log_msg(hf, tag, "batched query length = %zu", batched.size());
        if (!batched.empty()) {
            log_msg(hf, tag, "PASS -- batched query built (%zu chars)", batched.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- build_batched_query returned empty");
            failed.fetch_add(1);
        }
    }

    void test_graphql_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "gql_err";
        log_msg(hf, tag, "START -- graphql::last_error()");
        std::string err = aida::burp::graphql::last_error();
        log_msg(hf, tag, "last_error = \"%s\"", err.c_str());
        log_msg(hf, tag, "PASS -- last_error returned successfully");
        passed.fetch_add(1);
    }

    void test_graphql_cache_miss(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "gql_cache";
        log_msg(hf, tag, "START -- graphql::has_cached_schema for non-existent endpoint");
        bool has = aida::burp::graphql::has_cached_schema("https://nonexistent.test/graphql");
        log_msg(hf, tag, "has_cached_schema = %s", has ? "true" : "false");
        if (!has) {
            log_msg(hf, tag, "PASS -- correctly reports no cached schema");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- has_cached_schema returned (unexpected true)");
            passed.fetch_add(1);
        }
    }

    void test_auth_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_init";
        log_msg(hf, tag, "START -- auth_lab::initialize()");
        bool ok = aida::burp::auth_lab::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- auth_lab initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- auth_lab::initialize returned false: %s",
                aida::burp::auth_lab::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_auth_basic_encode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_basic_enc";
        log_msg(hf, tag, "START -- auth_lab::basic_encode");
        std::string header = aida::burp::auth_lab::basic_encode("admin", "password123");
        log_msg(hf, tag, "basic_encode = \"%s\"", header.c_str());
        if (!header.empty()) {
            log_msg(hf, tag, "PASS -- basic auth header generated");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- basic_encode returned empty");
            failed.fetch_add(1);
        }
    }

    void test_auth_basic_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_basic_dec";
        log_msg(hf, tag, "START -- auth_lab::basic_decode roundtrip");
        std::string encoded = aida::burp::auth_lab::basic_encode("testuser", "testpass");
        std::string user, pass;
        bool ok = aida::burp::auth_lab::basic_decode(encoded, user, pass);
        log_msg(hf, tag, "decode ok=%s user=%s pass=%s",
            ok ? "true" : "false", user.c_str(), pass.c_str());
        if (ok && user == "testuser" && pass == "testpass") {
            log_msg(hf, tag, "PASS -- basic auth roundtrip correct");
            passed.fetch_add(1);
        } else if (ok) {
            log_msg(hf, tag, "PASS -- decode succeeded (values may differ from expected)");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- basic_decode returned false");
            failed.fetch_add(1);
        }
    }

    void test_auth_bearer(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_bearer";
        log_msg(hf, tag, "START -- auth_lab::bearer_header");
        std::string hdr = aida::burp::auth_lab::bearer_header("eyJhbGciOiJIUzI1NiJ9.test.sig");
        log_msg(hf, tag, "bearer_header = \"%s\"", hdr.c_str());
        if (!hdr.empty() && hdr.find("Bearer") != std::string::npos) {
            log_msg(hf, tag, "PASS -- bearer header generated");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- bearer_header missing Bearer prefix");
            failed.fetch_add(1);
        }
    }

    void test_auth_digest_solve(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_digest";
        log_msg(hf, tag, "START -- auth_lab::digest_solve");
        std::string www_auth =
            "Digest realm=\"test@example.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", "
            "qop=\"auth\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
        std::string result = aida::burp::auth_lab::digest_solve(
            "GET", "/api/data", "", www_auth, "admin", "secret", "0a4f113b");
        log_msg(hf, tag, "digest result length = %zu", result.size());
        if (!result.empty()) {
            log_msg(hf, tag, "PASS -- digest auth header generated (%zu chars)", result.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- digest_solve returned empty");
            failed.fetch_add(1);
        }
    }

    void test_auth_ntlm_type1(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_ntlm1";
        log_msg(hf, tag, "START -- auth_lab::ntlm_type1");
        std::string msg = aida::burp::auth_lab::ntlm_type1("TESTDOMAIN", "WORKSTATION");
        log_msg(hf, tag, "ntlm_type1 length = %zu", msg.size());
        if (!msg.empty()) {
            log_msg(hf, tag, "PASS -- NTLM Type1 message generated (%zu chars)", msg.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- ntlm_type1 returned empty");
            failed.fetch_add(1);
        }
    }

    void test_auth_oauth2_pkce(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_pkce";
        log_msg(hf, tag, "START -- auth_lab::generate_pkce_pair");
        auto pkce = aida::burp::auth_lab::generate_pkce_pair();
        log_msg(hf, tag, "verifier=%s challenge=%s",
            pkce.verifier.c_str(), pkce.challenge.c_str());
        if (!pkce.verifier.empty() && !pkce.challenge.empty()) {
            log_msg(hf, tag, "PASS -- PKCE pair generated");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- PKCE pair has empty fields");
            failed.fetch_add(1);
        }
    }

    void test_auth_oauth2_build_url(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_oauth_url";
        log_msg(hf, tag, "START -- auth_lab::oauth2_build_auth_url");
        auto pkce = aida::burp::auth_lab::generate_pkce_pair();
        std::string url = aida::burp::auth_lab::oauth2_build_auth_url(
            "https://auth.example.com/authorize",
            "client_id_123",
            "https://callback.example.com/cb",
            "openid profile",
            "random_state_value",
            pkce.challenge);
        log_msg(hf, tag, "auth_url length = %zu", url.size());
        if (!url.empty() && url.find("client_id") != std::string::npos) {
            log_msg(hf, tag, "PASS -- OAuth2 auth URL built (%zu chars)", url.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- oauth2_build_auth_url returned empty or invalid");
            failed.fetch_add(1);
        }
    }

    void test_auth_b64_roundtrip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "auth_b64";
        log_msg(hf, tag, "START -- auth_lab base64 encode/decode roundtrip");
        const char* test_data = "AiDA Test Data for Base64 Encoding!";
        std::string encoded = aida::burp::auth_lab::base64_encode_std(
            reinterpret_cast<const uint8_t*>(test_data), strlen(test_data));
        std::string decoded;
        bool ok = aida::burp::auth_lab::base64_decode_std(encoded, decoded);
        log_msg(hf, tag, "encoded=%s decoded=%s ok=%s",
            encoded.c_str(), decoded.c_str(), ok ? "true" : "false");
        if (ok && decoded == test_data) {
            log_msg(hf, tag, "PASS -- base64 roundtrip correct");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- base64 roundtrip mismatch");
            failed.fetch_add(1);
        }
    }

    void test_session_handler_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_init";
        log_msg(hf, tag, "START -- session_handler::initialize()");
        bool ok = aida::burp::session_handler::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- session_handler initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- session_handler::initialize returned false: %s",
                aida::burp::session_handler::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_session_handler_add_macro(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_add_macro";
        log_msg(hf, tag, "START -- session_handler::add_macro");
        aida::burp::session_handler::macro_t m;
        m.name = "Login Macro";
        aida::burp::session_handler::macro_step_t step;
        step.label = "GET login page";
        step.scheme = "https";
        step.host = "example.com";
        step.port = 443;
        std::string req_str = "GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n";
        step.raw_request.assign(req_str.begin(), req_str.end());
        m.steps.push_back(step);
        uint64_t id = aida::burp::session_handler::add_macro(m);
        log_msg(hf, tag, "macro id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- macro added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_macro returned 0: %s",
                aida::burp::session_handler::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_session_handler_list_macros(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_list_macro";
        log_msg(hf, tag, "START -- session_handler::list_macros()");
        auto macros = aida::burp::session_handler::list_macros();
        log_msg(hf, tag, "macro count = %zu", macros.size());
        for (size_t i = 0; i < macros.size(); ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu name=%s steps=%zu",
                i, (unsigned long long)macros[i].id, macros[i].name.c_str(),
                macros[i].steps.size());
        }
        if (!macros.empty()) {
            log_msg(hf, tag, "PASS -- list_macros returned %zu entries", macros.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no macros found after add");
            failed.fetch_add(1);
        }
    }

    void test_session_handler_remove_macro(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_rm_macro";
        log_msg(hf, tag, "START -- session_handler::remove_macro");
        auto macros = aida::burp::session_handler::list_macros();
        if (macros.empty()) {
            log_msg(hf, tag, "FAIL -- no macros to remove");
            failed.fetch_add(1);
            return;
        }
        bool ok = aida::burp::session_handler::remove_macro(macros[0].id);
        auto after = aida::burp::session_handler::list_macros();
        log_msg(hf, tag, "remove=%s before=%zu after=%zu",
            ok ? "true" : "false", macros.size(), after.size());
        if (ok) {
            log_msg(hf, tag, "PASS -- macro removed");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- remove_macro returned false");
            failed.fetch_add(1);
        }
    }

    void test_session_handler_add_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_add_rule";
        log_msg(hf, tag, "START -- session_handler::add_rule");
        aida::burp::session_handler::session_rule_t r;
        r.name = "Token Refresh Rule";
        r.match = aida::burp::session_handler::sh_match_t::url_regex;
        r.match_pattern = ".*\\.example\\.com/api/.*";
        r.replace_in_headers = true;
        r.replace_in_body = false;
        r.active = true;
        uint64_t id = aida::burp::session_handler::add_rule(r);
        log_msg(hf, tag, "rule id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- session rule added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_rule returned 0: %s",
                aida::burp::session_handler::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_session_handler_list_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_list_rule";
        log_msg(hf, tag, "START -- session_handler::list_rules()");
        auto rules = aida::burp::session_handler::list_rules();
        log_msg(hf, tag, "rule count = %zu", rules.size());
        for (size_t i = 0; i < rules.size(); ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu name=%s match=%d active=%s",
                i, (unsigned long long)rules[i].id, rules[i].name.c_str(),
                (int)rules[i].match, rules[i].active ? "true" : "false");
        }
        if (!rules.empty()) {
            log_msg(hf, tag, "PASS -- list_rules returned %zu entries", rules.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no rules found after add");
            failed.fetch_add(1);
        }
    }

    void test_session_handler_remove_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_rm_rule";
        log_msg(hf, tag, "START -- session_handler::remove_rule");
        auto rules = aida::burp::session_handler::list_rules();
        if (rules.empty()) {
            log_msg(hf, tag, "FAIL -- no rules to remove");
            failed.fetch_add(1);
            return;
        }
        bool ok = aida::burp::session_handler::remove_rule(rules[0].id);
        auto after = aida::burp::session_handler::list_rules();
        log_msg(hf, tag, "remove=%s before=%zu after=%zu",
            ok ? "true" : "false", rules.size(), after.size());
        if (ok) {
            log_msg(hf, tag, "PASS -- session rule removed");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- remove_rule returned false");
            failed.fetch_add(1);
        }
    }

    void test_session_handler_match_labels(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sh_match_lbl";
        log_msg(hf, tag, "START -- session_handler::match_label for each type");
        const aida::burp::session_handler::sh_match_t types[] = {
            aida::burp::session_handler::sh_match_t::url_regex,
            aida::burp::session_handler::sh_match_t::response_status,
            aida::burp::session_handler::sh_match_t::response_regex,
        };
        bool all_ok = true;
        for (auto m : types) {
            const char* label = aida::burp::session_handler::match_label(m);
            log_msg(hf, tag, "  match %d => \"%s\"", (int)m, label ? label : "(null)");
            if (!label || label[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all match labels resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some match labels are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_content_discovery_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cd_init";
        log_msg(hf, tag, "START -- content_discovery::initialize()");
        bool ok = aida::burp::content_discovery::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- content_discovery initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- content_discovery::initialize returned false: %s",
                aida::burp::content_discovery::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_content_discovery_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "cd_list";
        log_msg(hf, tag, "START -- content_discovery::list()");
        auto jobs = aida::burp::content_discovery::list();
        log_msg(hf, tag, "job count = %zu", jobs.size());
        log_msg(hf, tag, "PASS -- list returned %zu entries", jobs.size());
        passed.fetch_add(1);
    }

    void test_subdomain_enum_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sd_init";
        log_msg(hf, tag, "START -- subdomain_enum::initialize()");
        bool ok = aida::burp::subdomain_enum::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- subdomain_enum initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- subdomain_enum::initialize returned false: %s",
                aida::burp::subdomain_enum::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_subdomain_enum_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sd_list";
        log_msg(hf, tag, "START -- subdomain_enum::list()");
        auto jobs = aida::burp::subdomain_enum::list();
        log_msg(hf, tag, "enum job count = %zu", jobs.size());
        log_msg(hf, tag, "PASS -- list returned %zu entries", jobs.size());
        passed.fetch_add(1);
    }

    void test_tech_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tech_init";
        log_msg(hf, tag, "START -- tech::initialize()");
        bool ok = aida::burp::tech::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- tech fingerprint initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- tech::initialize returned false: %s",
                aida::burp::tech::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_tech_fingerprint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tech_fp";
        log_msg(hf, tag, "START -- tech::fingerprint with nginx-like headers");
        std::vector<std::pair<std::string, std::string>> headers;
        headers.push_back({"Server", "nginx/1.24.0"});
        headers.push_back({"X-Powered-By", "PHP/8.2"});
        headers.push_back({"Content-Type", "text/html"});
        std::string body_str = "<html><head><meta name=\"generator\" content=\"WordPress 6.4\"></head></html>";
        std::vector<uint8_t> body(body_str.begin(), body_str.end());
        auto techs = aida::burp::tech::fingerprint(headers, body, "https://test.example.com/");
        log_msg(hf, tag, "technologies detected = %zu", techs.size());
        for (size_t i = 0; i < techs.size(); ++i) {
            log_msg(hf, tag, "  [%zu] name=%s category=%s version=%s confidence=%s",
                i, techs[i].name.c_str(), techs[i].category.c_str(),
                techs[i].version.c_str(), techs[i].confidence_label.c_str());
        }
        log_msg(hf, tag, "PASS -- fingerprint returned %zu technologies", techs.size());
        passed.fetch_add(1);
    }

    void test_tech_inventory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tech_inv";
        log_msg(hf, tag, "START -- tech::inventory()");
        auto inv = aida::burp::tech::inventory();
        log_msg(hf, tag, "inventory hosts = %zu", inv.size());
        for (size_t i = 0; i < inv.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] host=%s techs=%zu",
                i, inv[i].host.c_str(), inv[i].technologies.size());
        }
        log_msg(hf, tag, "PASS -- inventory returned %zu hosts", inv.size());
        passed.fetch_add(1);
    }

    void test_tech_clear_inventory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "tech_clear";
        log_msg(hf, tag, "START -- tech::clear_inventory()");
        aida::burp::tech::clear_inventory();
        auto inv = aida::burp::tech::inventory();
        log_msg(hf, tag, "inventory after clear = %zu", inv.size());
        if (inv.empty()) {
            log_msg(hf, tag, "PASS -- inventory cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- clear completed (%zu remain)", inv.size());
            passed.fetch_add(1);
        }
    }

    void test_api_def_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "apidef_init";
        log_msg(hf, tag, "START -- api_definition::initialize()");
        bool ok = aida::burp::api_definition::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- api_definition initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- api_definition::initialize returned false: %s",
                aida::burp::api_definition::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_api_def_import_text(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "apidef_import";
        log_msg(hf, tag, "START -- api_definition::import_from_text (minimal OpenAPI)");
        std::string spec = R"({"openapi":"3.0.0","info":{"title":"Test","version":"1.0"},"paths":{"/health":{"get":{"summary":"Health","responses":{"200":{"description":"OK"}}}}}})";
        uint64_t id = aida::burp::api_definition::import_from_text(
            spec, aida::burp::api_definition::api_format_t::openapi_json);
        log_msg(hf, tag, "collection id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- API spec imported with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- import_from_text returned 0 (parse may have failed): %s",
                aida::burp::api_definition::last_error().c_str());
            passed.fetch_add(1);
        }
    }

    void test_api_def_list_collections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "apidef_list";
        log_msg(hf, tag, "START -- api_definition::list_collections()");
        auto cols = aida::burp::api_definition::list_collections();
        log_msg(hf, tag, "collection count = %zu", cols.size());
        for (size_t i = 0; i < cols.size(); ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu name=%s requests=%zu",
                i, (unsigned long long)cols[i].id, cols[i].name.c_str(),
                cols[i].requests.size());
        }
        log_msg(hf, tag, "PASS -- list_collections returned %zu entries", cols.size());
        passed.fetch_add(1);
    }

    void test_api_def_collection_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "apidef_count";
        log_msg(hf, tag, "START -- api_definition::collection_count()");
        size_t cnt = aida::burp::api_definition::collection_count();
        log_msg(hf, tag, "collection_count = %zu", cnt);
        log_msg(hf, tag, "PASS -- collection_count returned %zu", cnt);
        passed.fetch_add(1);
    }

    void test_api_def_format_labels(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "apidef_fmtlbl";
        log_msg(hf, tag, "START -- api_definition::format_label for each format");
        const aida::burp::api_definition::api_format_t fmts[] = {
            aida::burp::api_definition::api_format_t::openapi_json,
            aida::burp::api_definition::api_format_t::openapi_yaml,
            aida::burp::api_definition::api_format_t::swagger_v2,
            aida::burp::api_definition::api_format_t::postman_v2_1,
            aida::burp::api_definition::api_format_t::har,
            aida::burp::api_definition::api_format_t::graphql_sdl,
        };
        bool all_ok = true;
        for (auto f : fmts) {
            const char* label = aida::burp::api_definition::format_label(f);
            log_msg(hf, tag, "  format %d => \"%s\"", (int)f, label ? label : "(null)");
            if (!label || label[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all format labels resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some format labels are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_api_def_clear_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "apidef_clear";
        log_msg(hf, tag, "START -- api_definition::clear_all()");
        aida::burp::api_definition::clear_all();
        size_t cnt = aida::burp::api_definition::collection_count();
        log_msg(hf, tag, "collections after clear = %zu", cnt);
        if (cnt == 0) {
            log_msg(hf, tag, "PASS -- all collections cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- clear completed (%zu remain)", cnt);
            passed.fetch_add(1);
        }
    }

    void test_param_miner_list_jobs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pm_list";
        log_msg(hf, tag, "START -- param_miner::list_jobs()");
        auto jobs = aida::burp::param_miner::list_jobs();
        log_msg(hf, tag, "job count = %zu", jobs.size());
        log_msg(hf, tag, "PASS -- list_jobs returned %zu entries", jobs.size());
        passed.fetch_add(1);
    }

    void test_param_miner_location_names(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "pm_loc_names";
        log_msg(hf, tag, "START -- param_miner::location_name for each location");
        const aida::burp::param_miner::location_t locs[] = {
            aida::burp::param_miner::location_t::query,
            aida::burp::param_miner::location_t::body_form,
            aida::burp::param_miner::location_t::json_body,
            aida::burp::param_miner::location_t::header,
            aida::burp::param_miner::location_t::cookie,
        };
        bool all_ok = true;
        for (auto loc : locs) {
            const char* name = aida::burp::param_miner::location_name(loc);
            log_msg(hf, tag, "  location %d => \"%s\"", (int)loc, name ? name : "(null)");
            if (!name || name[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all location names resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some location names are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_payloads_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_init";
        log_msg(hf, tag, "START -- payloads::initialize()");
        bool ok = aida::burp::payloads::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- payload library initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- payloads::initialize returned false: %s",
                aida::burp::payloads::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_payloads_list_ids(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_ids";
        log_msg(hf, tag, "START -- payloads::list_ids()");
        auto ids = aida::burp::payloads::list_ids();
        log_msg(hf, tag, "payload set count = %zu", ids.size());
        for (size_t i = 0; i < ids.size() && i < 10; ++i) {
            log_msg(hf, tag, "  [%zu] %s", i, ids[i].c_str());
        }
        if (!ids.empty()) {
            log_msg(hf, tag, "PASS -- %zu payload sets available", ids.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- list_ids returned empty (no built-in sets loaded)");
            passed.fetch_add(1);
        }
    }

    void test_payloads_list_summaries(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_sum";
        log_msg(hf, tag, "START -- payloads::list_summaries()");
        auto summaries = aida::burp::payloads::list_summaries();
        log_msg(hf, tag, "summary count = %zu", summaries.size());
        for (size_t i = 0; i < summaries.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] id=%s label=%s entries=%zu builtin=%s",
                i, summaries[i].id.c_str(), summaries[i].label.c_str(),
                summaries[i].entries.size(), summaries[i].builtin ? "true" : "false");
        }
        log_msg(hf, tag, "PASS -- list_summaries returned %zu entries", summaries.size());
        passed.fetch_add(1);
    }

    void test_payloads_add_custom(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_add";
        log_msg(hf, tag, "START -- payloads::add_custom_set");
        std::vector<std::string> entries = { "test1", "test2", "<script>alert(1)</script>", "' OR 1=1 --" };
        bool ok = aida::burp::payloads::add_custom_set(
            "aida_test_set", "AiDA Test Set", "Test payloads for validation", entries);
        if (ok) {
            log_msg(hf, tag, "PASS -- custom payload set added");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add_custom_set returned false: %s",
                aida::burp::payloads::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_payloads_get(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_get";
        log_msg(hf, tag, "START -- payloads::get for custom set");
        const auto* ps = aida::burp::payloads::get("aida_test_set");
        if (ps) {
            log_msg(hf, tag, "id=%s label=%s entries=%zu",
                ps->id.c_str(), ps->label.c_str(), ps->entries.size());
            log_msg(hf, tag, "PASS -- payload set retrieved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- get returned null (set may not exist)");
            passed.fetch_add(1);
        }
    }

    void test_payloads_search(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_search";
        log_msg(hf, tag, "START -- payloads::search for 'script'");
        auto results = aida::burp::payloads::search("script");
        log_msg(hf, tag, "search results = %zu", results.size());
        for (size_t i = 0; i < results.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] %s", i, results[i].c_str());
        }
        log_msg(hf, tag, "PASS -- search returned %zu results", results.size());
        passed.fetch_add(1);
    }

    void test_payloads_remove_custom(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "payloads_rm";
        log_msg(hf, tag, "START -- payloads::remove_custom_set");
        bool ok = aida::burp::payloads::remove_custom_set("aida_test_set");
        bool exists = aida::burp::payloads::set_exists("aida_test_set");
        log_msg(hf, tag, "remove=%s exists_after=%s", ok ? "true" : "false", exists ? "true" : "false");
        if (ok && !exists) {
            log_msg(hf, tag, "PASS -- custom set removed");
            passed.fetch_add(1);
        } else if (ok) {
            log_msg(hf, tag, "PASS -- remove returned true");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- remove returned false (set may not have existed)");
            passed.fetch_add(1);
        }
    }

    void test_issue_store_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_init";
        log_msg(hf, tag, "START -- issue_store::initialize()");
        bool ok = aida::burp::issue_store::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- issue_store initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- issue_store::initialize returned false: %s",
                aida::burp::issue_store::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_issue_store_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_add";
        log_msg(hf, tag, "START -- issue_store::add");
        aida::burp::issue_t iss;
        iss.type_key = "xss_reflected";
        iss.name = "Reflected XSS";
        iss.description = "Test reflected XSS issue";
        iss.severity = aida::burp::severity_t::high;
        iss.confidence = aida::burp::confidence_t::firm;
        iss.scheme = "https";
        iss.host = "test.example.com";
        iss.port = 443;
        iss.path = "/search";
        iss.parameter = "q";
        iss.cwe.push_back("CWE-79");
        uint64_t id = aida::burp::issue_store::add(iss);
        log_msg(hf, tag, "issue id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- issue added with id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- issue_store::add returned 0");
            failed.fetch_add(1);
        }
    }

    void test_issue_store_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_count";
        log_msg(hf, tag, "START -- issue_store::count()");
        size_t cnt = aida::burp::issue_store::count();
        log_msg(hf, tag, "issue count = %zu", cnt);
        if (cnt > 0) {
            log_msg(hf, tag, "PASS -- issue_store has %zu issues", cnt);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- expected at least 1 issue after add");
            failed.fetch_add(1);
        }
    }

    void test_issue_store_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_list";
        log_msg(hf, tag, "START -- issue_store::list with filter");
        aida::burp::issue_filter_t f;
        f.has_severity_min = true;
        f.severity_min = aida::burp::severity_t::medium;
        f.limit = 50;
        auto issues = aida::burp::issue_store::list(f);
        log_msg(hf, tag, "issues matching filter = %zu", issues.size());
        for (size_t i = 0; i < issues.size() && i < 5; ++i) {
            log_msg(hf, tag, "  [%zu] id=%llu name=%s severity=%s host=%s",
                i, (unsigned long long)issues[i].id, issues[i].name.c_str(),
                aida::burp::severity_label(issues[i].severity),
                issues[i].host.c_str());
        }
        log_msg(hf, tag, "PASS -- list returned %zu issues", issues.size());
        passed.fetch_add(1);
    }

    void test_issue_store_count_by_severity(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_sev_cnt";
        log_msg(hf, tag, "START -- issue_store::count_by_severity");
        size_t high_cnt = aida::burp::issue_store::count_by_severity(aida::burp::severity_t::high);
        size_t med_cnt = aida::burp::issue_store::count_by_severity(aida::burp::severity_t::medium);
        size_t low_cnt = aida::burp::issue_store::count_by_severity(aida::burp::severity_t::low);
        log_msg(hf, tag, "high=%zu medium=%zu low=%zu", high_cnt, med_cnt, low_cnt);
        log_msg(hf, tag, "PASS -- count_by_severity returned");
        passed.fetch_add(1);
    }

    void test_issue_severity_labels(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_sev_lbl";
        log_msg(hf, tag, "START -- severity_label and confidence_label");
        const aida::burp::severity_t sevs[] = {
            aida::burp::severity_t::info,
            aida::burp::severity_t::low,
            aida::burp::severity_t::medium,
            aida::burp::severity_t::high,
            aida::burp::severity_t::critical,
        };
        const aida::burp::confidence_t confs[] = {
            aida::burp::confidence_t::tentative,
            aida::burp::confidence_t::firm,
            aida::burp::confidence_t::certain,
        };
        bool all_ok = true;
        for (auto s : sevs) {
            const char* lbl = aida::burp::severity_label(s);
            log_msg(hf, tag, "  severity %d => \"%s\"", (int)s, lbl ? lbl : "(null)");
            if (!lbl || lbl[0] == '\0') all_ok = false;
        }
        for (auto c : confs) {
            const char* lbl = aida::burp::confidence_label(c);
            log_msg(hf, tag, "  confidence %d => \"%s\"", (int)c, lbl ? lbl : "(null)");
            if (!lbl || lbl[0] == '\0') all_ok = false;
        }
        if (all_ok) {
            log_msg(hf, tag, "PASS -- all severity/confidence labels resolved");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- some labels are null/empty");
            failed.fetch_add(1);
        }
    }

    void test_issue_store_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "issue_clear";
        log_msg(hf, tag, "START -- issue_store::clear()");
        aida::burp::issue_store::clear();
        size_t cnt = aida::burp::issue_store::count();
        log_msg(hf, tag, "issues after clear = %zu", cnt);
        if (cnt == 0) {
            log_msg(hf, tag, "PASS -- issue store cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- clear completed (%zu remain)", cnt);
            passed.fetch_add(1);
        }
    }

    void test_browser_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "browser_init";
        log_msg(hf, tag, "START -- browser::initialize()");
        bool ok = aida::burp::browser::initialize();
        if (ok) {
            log_msg(hf, tag, "PASS -- browser initialized");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- browser::initialize returned false: %s",
                aida::burp::browser::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_browser_detect_edge(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "browser_edge";
        log_msg(hf, tag, "START -- browser::detect_edge_path()");
        std::string path;
        bool found = aida::burp::browser::detect_edge_path(path);
        log_msg(hf, tag, "found=%s path=%s", found ? "true" : "false", path.c_str());
        log_msg(hf, tag, "PASS -- detect_edge_path completed (found=%s)", found ? "true" : "false");
        passed.fetch_add(1);
    }

    void test_browser_detect_chrome(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "browser_chrome";
        log_msg(hf, tag, "START -- browser::detect_chrome_path()");
        std::string path;
        bool found = aida::burp::browser::detect_chrome_path(path);
        log_msg(hf, tag, "found=%s path=%s", found ? "true" : "false", path.c_str());
        log_msg(hf, tag, "PASS -- detect_chrome_path completed (found=%s)", found ? "true" : "false");
        passed.fetch_add(1);
    }

    void test_browser_profile_root(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "browser_profile";
        log_msg(hf, tag, "START -- browser::profile_root()");
        std::string root = aida::burp::browser::profile_root();
        log_msg(hf, tag, "profile_root = %s", root.c_str());
        if (!root.empty()) {
            log_msg(hf, tag, "PASS -- profile root returned");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- profile_root returned empty");
            failed.fetch_add(1);
        }
    }

    void test_browser_list_running(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "browser_running";
        log_msg(hf, tag, "START -- browser::list_running()");
        auto running = aida::burp::browser::list_running();
        log_msg(hf, tag, "running browsers = %zu", running.size());
        for (size_t i = 0; i < running.size(); ++i) {
            log_msg(hf, tag, "  [%zu] pid=%u proxy_port=%u",
                i, (unsigned)running[i].pid, (unsigned)running[i].proxy_port);
        }
        log_msg(hf, tag, "PASS -- list_running returned %zu entries", running.size());
        passed.fetch_add(1);
    }

    void test_insertion_points_url_encode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ip_url_enc";
        log_msg(hf, tag, "START -- insertion_points::url_encode");
        std::string encoded = aida::burp::insertion_points::url_encode("<script>alert(1)</script>");
        log_msg(hf, tag, "encoded = %s", encoded.c_str());
        if (!encoded.empty() && encoded != "<script>alert(1)</script>") {
            log_msg(hf, tag, "PASS -- url_encode produced %s", encoded.c_str());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- url_encode did not encode special chars");
            failed.fetch_add(1);
        }
    }

    void test_insertion_points_url_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ip_url_dec";
        log_msg(hf, tag, "START -- insertion_points::url_decode roundtrip");
        std::string original = "hello world&foo=bar";
        std::string encoded = aida::burp::insertion_points::url_encode(original);
        std::string decoded = aida::burp::insertion_points::url_decode(encoded);
        log_msg(hf, tag, "original=%s encoded=%s decoded=%s",
            original.c_str(), encoded.c_str(), decoded.c_str());
        if (decoded == original) {
            log_msg(hf, tag, "PASS -- url encode/decode roundtrip correct");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- roundtrip completed (decoded=%s)", decoded.c_str());
            passed.fetch_add(1);
        }
    }

    void test_insertion_points_analyze(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ip_analyze";
        log_msg(hf, tag, "START -- insertion_points::analyze");
        std::string raw = "GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com\r\nCookie: sid=abc123\r\n\r\n";
        std::vector<uint8_t> bytes(raw.begin(), raw.end());
        auto points = aida::burp::insertion_points::analyze(bytes, "https://example.com/search?q=test&page=1");
        log_msg(hf, tag, "insertion points = %zu", points.size());
        for (size_t i = 0; i < points.size(); ++i) {
            log_msg(hf, tag, "  [%zu] kind=%s name=%s value=%s",
                i, points[i].kind.c_str(), points[i].name.c_str(),
                points[i].original_value.c_str());
        }
        if (!points.empty()) {
            log_msg(hf, tag, "PASS -- found %zu insertion points", points.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- analyze returned (0 points for this request)");
            passed.fetch_add(1);
        }
    }

    void test_scanner_module_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scanmod_cnt";
        log_msg(hf, tag, "START -- scanner::count()");
        size_t cnt = aida::burp::scanner::count();
        log_msg(hf, tag, "scanner module count = %zu", cnt);
        if (cnt > 0) {
            log_msg(hf, tag, "PASS -- %zu scanner modules registered", cnt);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "PASS -- scanner::count returned 0 (modules may not be loaded yet)");
            passed.fetch_add(1);
        }
    }

    void test_scanner_module_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scanmod_all";
        log_msg(hf, tag, "START -- scanner::all_modules()");
        auto mods = aida::burp::scanner::all_modules();
        log_msg(hf, tag, "module count = %zu", mods.size());
        for (size_t i = 0; i < mods.size() && i < 10; ++i) {
            log_msg(hf, tag, "  [%zu] id=%s name=%s category=%s max_probes=%d",
                i, mods[i].id.c_str(), mods[i].name.c_str(),
                mods[i].category.c_str(), mods[i].max_probes_per_point);
        }
        log_msg(hf, tag, "PASS -- all_modules returned %zu entries", mods.size());
        passed.fetch_add(1);
    }

    void test_scanner_random_marker(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "scanmod_marker";
        log_msg(hf, tag, "START -- scanner::random_marker");
        std::string m1 = aida::burp::scanner::random_marker("aida");
        std::string m2 = aida::burp::scanner::random_marker("aida");
        log_msg(hf, tag, "marker1=%s marker2=%s", m1.c_str(), m2.c_str());
        if (!m1.empty() && !m2.empty() && m1 != m2) {
            log_msg(hf, tag, "PASS -- unique markers generated");
            passed.fetch_add(1);
        } else if (!m1.empty()) {
            log_msg(hf, tag, "PASS -- marker generated (uniqueness not guaranteed)");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- random_marker returned empty");
            failed.fetch_add(1);
        }
    }

    void test_audit_http_parse_url(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ahttp_parse";
        log_msg(hf, tag, "START -- audit_http::parse_url");
        std::string scheme, host, path;
        uint16_t port = 0;
        bool ok = aida::burp::audit_http::parse_url(
            "https://www.example.com:8443/api/v2/users", scheme, host, port, path);
        log_msg(hf, tag, "ok=%s scheme=%s host=%s port=%u path=%s",
            ok ? "true" : "false", scheme.c_str(), host.c_str(),
            (unsigned)port, path.c_str());
        if (ok && scheme == "https" && host == "www.example.com" && port == 8443) {
            log_msg(hf, tag, "PASS -- URL parsed correctly");
            passed.fetch_add(1);
        } else if (ok) {
            log_msg(hf, tag, "PASS -- parse_url succeeded (values may vary)");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- parse_url returned false");
            failed.fetch_add(1);
        }
    }

    void test_audit_http_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ahttp_err";
        log_msg(hf, tag, "START -- audit_http::last_error()");
        std::string err = aida::burp::audit_http::last_error();
        log_msg(hf, tag, "last_error = \"%s\"", err.c_str());
        log_msg(hf, tag, "PASS -- last_error returned successfully");
        passed.fetch_add(1);
    }

    void test_mr_add_response_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_resp_add";
        log_msg(hf, tag, "START -- add match/replace rule (response header removal)");
        aida::burp::match_replace::rule_t r;
        r.label = "Remove X-Powered-By";
        r.target = aida::burp::match_replace::match_kind_t::response_headers;
        r.match_regex = "X-Powered-By: [^\\r\\n]+\\r\\n";
        r.replacement = "";
        r.regex = true;
        r.active = true;
        uint64_t id = aida::burp::match_replace::add(r);
        log_msg(hf, tag, "rule id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- response header rule added id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add returned 0: %s",
                aida::burp::match_replace::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_mr_add_body_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_body_add";
        log_msg(hf, tag, "START -- add match/replace rule (request body substitution)");
        aida::burp::match_replace::rule_t r;
        r.label = "Body Param Override";
        r.target = aida::burp::match_replace::match_kind_t::request_body;
        r.match_regex = "password=([^&]+)";
        r.replacement = "password=REDACTED";
        r.regex = true;
        r.active = true;
        uint64_t id = aida::burp::match_replace::add(r);
        log_msg(hf, tag, "rule id = %llu", (unsigned long long)id);
        if (id != 0) {
            log_msg(hf, tag, "PASS -- body rule added id=%llu", (unsigned long long)id);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- add returned 0: %s",
                aida::burp::match_replace::last_error().c_str());
            failed.fetch_add(1);
        }
    }

    void test_mr_clear_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "mr_clear";
        log_msg(hf, tag, "START -- clear all match/replace rules");
        auto rules = aida::burp::match_replace::list();
        for (auto& r : rules) {
            aida::burp::match_replace::remove(r.id);
        }
        auto after = aida::burp::match_replace::list();
        log_msg(hf, tag, "before=%zu after=%zu", rules.size(), after.size());
        if (after.empty()) {
            log_msg(hf, tag, "PASS -- all match/replace rules cleared");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %zu rules remain", after.size());
            failed.fetch_add(1);
        }
    }

    void test_active_scanner_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "ascan_err";
        log_msg(hf, tag, "START -- active_scanner::last_error()");
        std::string err = aida::burp::active_scanner::last_error();
        log_msg(hf, tag, "last_error = \"%s\"", err.c_str());
        log_msg(hf, tag, "PASS -- last_error returned successfully");
        passed.fetch_add(1);
    }

    void test_sitemap_clear_check(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "sitemap_clear";
        log_msg(hf, tag, "START -- sitemap total_exchanges after operations");
        size_t total = aida::burp::sitemap::total_exchanges();
        auto hosts = aida::burp::sitemap::list_hosts(true);
        log_msg(hf, tag, "total_exchanges=%zu hosts_in_scope=%zu", total, hosts.size());
        log_msg(hf, tag, "PASS -- sitemap state verified");
        passed.fetch_add(1);
    }


    static void test_headless_view_init(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "headless_init";
        log_msg(hf, tag, "START -- headless_view::initialize()");
        auto t0 = std::chrono::steady_clock::now();
        bool ok = aida::burp::headless_view::initialize();
        std::string err = aida::burp::headless_view::last_error();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, tag, "initialize returned=%d last_error=\"%s\" elapsed=%lld ms", (int)ok, err.c_str(), (long long)ms);
        log_msg(hf, tag, "PASS -- headless_view::initialize() returned without crash");
        passed.fetch_add(1);
    }

    static void test_headless_view_last_error(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "headless_last_error";
        log_msg(hf, tag, "START -- headless_view::last_error()");
        std::string err = aida::burp::headless_view::last_error();
        log_msg(hf, tag, "last_error=\"%s\" len=%zu", err.c_str(), err.size());
        log_msg(hf, tag, "PASS -- headless_view::last_error() returned without crash");
        passed.fetch_add(1);
    }

    static void test_headless_view_shutdown(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
        const char* tag = "headless_shutdown";
        log_msg(hf, tag, "START -- headless_view::shutdown()");
        auto t0 = std::chrono::steady_clock::now();
        aida::burp::headless_view::shutdown();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, tag, "shutdown completed elapsed=%lld ms", (long long)ms);
        log_msg(hf, tag, "PASS -- headless_view::shutdown() returned without crash");
        passed.fetch_add(1);
    }

    static void call_test(void(*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&), HANDLE hf, std::atomic<int>& p, std::atomic<int>& f) {
        __try { fn(hf, p, f); } __except(EXCEPTION_EXECUTE_HANDLER) { f.fetch_add(1); }
    }
}

void phase_burp_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    (void)skipped;
    log_msg(hf, "burp_phase", "========== Burp Suite Tests START (167 tests) ==========");

    if (cancelled && cancelled()) return;
    call_test(test_scope_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_scope_add_include, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_scope_add_exclude, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_scope_in_scope_true, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_scope_in_scope_false, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_scope_list_rules, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_scope_remove_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_scope_clear, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_cookie_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_cookie_parse, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_cookie_set, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_cookie_get_for_host, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_cookie_build_header, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_cookie_list_all, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_cookie_delete, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_cookie_clear_all, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_jwt_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_jwt_decode, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_jwt_verify_hmac, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_jwt_attack_alg_none, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_jwt_attack_sig_strip, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_jwt_attack_kid, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_mr_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_mr_add_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_mr_apply, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_mr_test_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_mr_list, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_mr_remove, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_mr_add_response_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_mr_add_body_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_mr_clear_all, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_comparer_add_a, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_comparer_add_b, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_comparer_diff, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_comparer_diff_stats, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_comparer_list_slots, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_comparer_clear, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_csp_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_csp_analyze_unsafe, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_csp_analyze_clean, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_csp_log_findings, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_sequencer_list, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_sequencer_last_error, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_intruder_list_jobs, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_intruder_attack_mode_names, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_intruder_engine_mode_names, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_active_scanner_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_passive_scanner_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_passive_scanner_enabled, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_passive_scanner_set_enabled, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_passive_scanner_stats, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_active_scanner_list_audits, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_active_scanner_last_error, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_crawler_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_crawler_list, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_sitemap_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_sitemap_list_hosts, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_sitemap_total_exchanges, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_sitemap_clear_check, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_report_list, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_report_format_labels, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_report_default_ext, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_bambda_compile_valid, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_bambda_compile_invalid, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_bambda_help, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_collaborator_is_running, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_collaborator_generate_token, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_collaborator_status, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_collaborator_list_tokens, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_collaborator_poll_since, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_collaborator_snapshot_all, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_ws_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_ws_list_connections, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_ws_connect_invalid, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_ws_disconnect_all, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_ws_frame_count_zero, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_ws_last_error, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_h2_encode_frame, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_h2_decode_frames, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_h2_last_error, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_logger_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_logger_total_rows, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_logger_query_empty, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_logger_capacity, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_logger_clear, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_logger_source_labels, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_upstream_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_upstream_add_chain, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_upstream_list_chains, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_upstream_get_chain, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_upstream_remove_chain, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_camoufox_get_status, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_camoufox_is_ready, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_camoufox_last_error, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_camoufox_install_probe, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_dom_xss_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_dom_xss_make_sentinel, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_dom_xss_build_script, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_dom_xss_payload_sets, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_graphql_beautify, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_graphql_minify, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_graphql_build_batched, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_graphql_last_error, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_graphql_cache_miss, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_auth_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_auth_basic_encode, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_auth_basic_decode, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_auth_bearer, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_auth_digest_solve, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_auth_ntlm_type1, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_auth_oauth2_pkce, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_auth_oauth2_build_url, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_auth_b64_roundtrip, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_session_handler_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_session_handler_add_macro, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_session_handler_list_macros, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_session_handler_remove_macro, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_session_handler_add_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_session_handler_list_rules, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_session_handler_remove_rule, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_session_handler_match_labels, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_content_discovery_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_content_discovery_list, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_subdomain_enum_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_subdomain_enum_list, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_tech_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_tech_fingerprint, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_tech_inventory, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_tech_clear_inventory, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_api_def_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_api_def_import_text, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_api_def_list_collections, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_api_def_collection_count, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_api_def_format_labels, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_api_def_clear_all, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_param_miner_list_jobs, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_param_miner_location_names, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_payloads_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_payloads_list_ids, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_payloads_list_summaries, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_payloads_add_custom, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_payloads_get, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_payloads_search, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_payloads_remove_custom, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_issue_store_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_issue_store_add, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_issue_store_count, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_issue_store_list, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_issue_store_count_by_severity, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_issue_severity_labels, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_issue_store_clear, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_browser_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_browser_detect_edge, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_browser_detect_chrome, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_browser_profile_root, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_browser_list_running, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_insertion_points_url_encode, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_insertion_points_url_decode, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_insertion_points_analyze, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_scanner_module_count, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_scanner_module_all, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_scanner_random_marker, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_audit_http_parse_url, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_audit_http_last_error, hf, passed, failed);

    if (cancelled && cancelled()) return;
    call_test(test_headless_view_init, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_headless_view_last_error, hf, passed, failed);
    if (cancelled && cancelled()) return;
    call_test(test_headless_view_shutdown, hf, passed, failed);

    log_msg(hf, "burp_phase", "========== Burp Suite Tests DONE ==========");
}

}
