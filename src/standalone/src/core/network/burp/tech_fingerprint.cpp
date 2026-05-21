#include "tech_fingerprint.hpp"
#include "burp_events.hpp"
#include "issue.hpp"
#include "../../infra/event_bus.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <map>
#include <mutex>
#include <regex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace aida {
namespace burp {
namespace tech {

namespace {

struct rule_t
{
    const char* name;
    const char* category;
    const char* header_name;
    const char* header_regex;
    const char* body_regex;
    const char* version_regex;
    const char* version_source;
};

static const rule_t kRules[] = {
    { "jQuery",       "JavaScript library", nullptr, nullptr, "jQuery\\s+v?([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", "jQuery\\s+v?([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", "body" },
    { "React",        "JavaScript library", nullptr, nullptr, "(react(?:-dom)?@|react\\.production\\.min\\.js|/react/|react\\.js)", "react(?:-dom)?@([0-9]+\\.[0-9]+\\.[0-9]+)", "body" },
    { "Vue.js",       "JavaScript library", nullptr, nullptr, "(Vue\\.js v|vue@|vuejs|/vue/)", "Vue\\.js v([0-9]+\\.[0-9]+\\.[0-9]+)", "body" },
    { "Angular",      "JavaScript library", nullptr, nullptr, "(ng-version=|@angular/|angular\\.min\\.js)", "ng-version=\"([0-9]+\\.[0-9]+\\.[0-9]+)\"", "body" },
    { "Next.js",      "JavaScript framework", "x-powered-by", "Next\\.js", "(__next|/_next/static/)", "Next\\.js\\s*v?([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", "header" },
    { "Svelte",       "JavaScript framework", nullptr, nullptr, "(svelte-|/svelte\\.js|__sveltekit_)", nullptr, nullptr },
    { "Bootstrap",    "UI framework", nullptr, nullptr, "(bootstrap\\.min\\.css|Bootstrap v|class=\"container)", "Bootstrap v([0-9]+\\.[0-9]+\\.[0-9]+)", "body" },
    { "Tailwind CSS", "UI framework", nullptr, nullptr, "(tailwindcss|/tailwind|tw-class|class=\"[^\"]*?(?:flex |grid |bg-)[^\"]*?\")", nullptr, nullptr },
    { "Apache",       "Web server", "server", "Apache(?:/([0-9]+\\.[0-9]+(?:\\.[0-9]+)?))?", nullptr, "Apache/([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", "header" },
    { "Nginx",        "Web server", "server", "nginx(?:/([0-9]+\\.[0-9]+(?:\\.[0-9]+)?))?", nullptr, "nginx/([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", "header" },
    { "Microsoft IIS","Web server", "server", "Microsoft-IIS(?:/([0-9]+\\.[0-9]+))?", nullptr, "Microsoft-IIS/([0-9]+\\.[0-9]+)", "header" },
    { "Caddy",        "Web server", "server", "Caddy", nullptr, nullptr, nullptr },
    { "PHP",          "Language", "x-powered-by", "PHP(?:/([0-9]+\\.[0-9]+(?:\\.[0-9]+)?))?", nullptr, "PHP/([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", "header" },
    { "ASP.NET",      "Framework", "x-powered-by", "ASP\\.NET", nullptr, nullptr, nullptr },
    { "Express",      "Framework", "x-powered-by", "Express", nullptr, nullptr, nullptr },
    { "Django",       "Framework", nullptr, nullptr, "csrfmiddlewaretoken|/admin/jsi18n/", nullptr, nullptr },
    { "Flask",        "Framework", "server", "Werkzeug(?:/([0-9]+\\.[0-9]+(?:\\.[0-9]+)?))?", nullptr, "Werkzeug/([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", "header" },
    { "Ruby on Rails","Framework", "x-powered-by", "(?:Phusion Passenger|Rails)", "<meta name=\"csrf-param\" content=\"authenticity_token\"", nullptr, nullptr },
    { "Spring Boot",  "Framework", nullptr, nullptr, "(/webjars/|Whitelabel Error Page)", nullptr, nullptr },
    { "Laravel",      "Framework", nullptr, "laravel_session", "(laravel_token|XSRF-TOKEN)", nullptr, nullptr },
    { "WordPress",    "CMS", nullptr, nullptr, "(wp-content/|wp-includes/|generator\" content=\"WordPress)", "<meta name=\"generator\" content=\"WordPress\\s+([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)\"", "body" },
    { "Drupal",       "CMS", "x-generator", "Drupal", "(/sites/default/|Drupal\\.settings)", "Drupal\\s+([0-9]+(?:\\.[0-9]+)?)", "body" },
    { "Joomla",       "CMS", nullptr, nullptr, "(/media/jui/|content=\"Joomla)", "content=\"Joomla!\\s+([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)\"", "body" },
    { "Cloudflare",   "CDN / WAF", "server", "cloudflare", nullptr, nullptr, nullptr },
    { "Akamai",       "CDN", "x-akamai-transformed", ".*", nullptr, nullptr, nullptr },
    { "AWS CloudFront","CDN", "x-amz-cf-id", ".*", nullptr, nullptr, nullptr },
    { "Fastly",       "CDN", "x-served-by", "cache-(?:fra|lhr|jfk|sea|atl|iad|den|sfo|nrt|hkg)", nullptr, nullptr, nullptr },
    { "Stripe.js",    "Payments", nullptr, nullptr, "(js\\.stripe\\.com|Stripe\\.setPublishableKey)", nullptr, nullptr },
    { "Auth0",        "Auth provider", nullptr, nullptr, "(auth0\\.com|@auth0/)", nullptr, nullptr },
    { "Okta",         "Auth provider", nullptr, nullptr, "(okta-signin-widget|\\.okta\\.com/)", nullptr, nullptr },
    { "OneLogin",     "Auth provider", nullptr, nullptr, "onelogin\\.com", nullptr, nullptr },
    { "Plausible",    "Analytics", nullptr, nullptr, "plausible\\.io/js/", nullptr, nullptr },
    { "Segment",      "Analytics", nullptr, nullptr, "(cdn\\.segment\\.com|analytics\\.js)", nullptr, nullptr },
    { "Google Analytics", "Analytics", nullptr, nullptr, "(google-analytics\\.com/(?:ga|analytics)\\.js|gtag\\('config')", nullptr, nullptr },
    { "Google Tag Manager", "Tag manager", nullptr, nullptr, "googletagmanager\\.com/gtm\\.js", nullptr, nullptr },
    { "Hotjar",       "Analytics", nullptr, nullptr, "(static\\.hotjar\\.com|hj\\(\")", nullptr, nullptr },
};

std::mutex& err_mtx()
{
    static std::mutex m;
    return m;
}

std::string& err_slot()
{
    static std::string e;
    return e;
}

void set_err(const std::string& m)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = m;
}

std::atomic<bool>& initialized_flag()
{
    static std::atomic<bool> f{false};
    return f;
}

aida::events::subscription_handle_t& subscription_handle()
{
    static aida::events::subscription_handle_t h;
    return h;
}

struct inv_state_t
{
    std::mutex                                                       mtx;
    std::unordered_map<std::string, std::map<std::string, tech_t>>   by_host;
    std::unordered_set<std::string>                                  issued_pairs;
};

inv_state_t& inv()
{
    static inv_state_t s;
    return s;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string to_lower(const std::string& s)
{
    std::string r;
    r.reserve(s.size());
    for (char c : s) r.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return r;
}

std::string header_get(const std::vector<std::pair<std::string, std::string>>& h, const std::string& name)
{
    std::string lc = to_lower(name);
    for (const auto& p : h) {
        if (to_lower(p.first) == lc) return p.second;
    }
    return std::string();
}

void handle_exchange(const exchange_observed_t& e)
{
    if (!initialized_flag().load()) {
        diag::log_tagged_fmt("tech_fp", "handle_exchange skipped not_initialized");
        return;
    }
    diag::log_tagged_fmt("tech_fp", "handle_exchange entry host=%s path=%s exchange_id=%llu",
        e.host.c_str(), e.path.c_str(), static_cast<unsigned long long>(e.id));
    std::string url = e.scheme.empty() ? std::string("http") : e.scheme;
    url += "://";
    url += e.host;
    url += e.path;
    auto detected = fingerprint(e.resp_headers, e.resp_body, url);
    if (detected.empty()) {
        diag::log_tagged_fmt("tech_fp", "handle_exchange no_techs_detected host=%s", e.host.c_str());
        return;
    }
    diag::log_tagged_fmt("tech_fp", "handle_exchange detected count=%zu host=%s",
        detected.size(), e.host.c_str());

    auto& s = inv();
    std::vector<tech_t> new_to_emit;
    {
        std::lock_guard<std::mutex> lk(s.mtx);
        auto& host_map = s.by_host[e.host];
        for (const auto& t : detected) {
            auto key_pair = e.host + "|" + t.name;
            auto it = host_map.find(t.name);
            if (it == host_map.end() || (!t.version.empty() && it->second.version != t.version)) {
                host_map[t.name] = t;
                if (!s.issued_pairs.count(key_pair)) {
                    s.issued_pairs.insert(key_pair);
                    new_to_emit.push_back(t);
                    diag::log_tagged_fmt("tech_fp", "handle_exchange new_tech name=%s version=%s category=%s",
                        t.name.c_str(), t.version.c_str(), t.category.c_str());
                } else {
                    diag::log_tagged_fmt("tech_fp", "handle_exchange tech_already_issued name=%s", t.name.c_str());
                }
            } else {
                diag::log_tagged_fmt("tech_fp", "handle_exchange tech_already_known name=%s", t.name.c_str());
            }
        }
    }

    diag::log_tagged_fmt("tech_fp", "handle_exchange emitting_issues count=%zu", new_to_emit.size());
    for (const auto& t : new_to_emit) {
        diag::log_tagged_fmt("tech_fp", "handle_exchange adding_issue name=%s version=%s host=%s",
            t.name.c_str(), t.version.c_str(), e.host.c_str());
        issue_t iss;
        iss.type_key = "tech_fingerprint";
        iss.name = std::string("Technology detected: ") + t.name + (t.version.empty() ? std::string() : (" " + t.version));
        iss.severity = severity_t::info;
        iss.confidence = confidence_t::firm;
        iss.host = e.host;
        iss.port = e.port;
        iss.scheme = e.scheme;
        iss.path = e.path;
        iss.src_exchange_id = e.id;
        iss.seen_ms = now_ms();
        iss.description = std::string("Technology fingerprint identified ") + t.name +
                          (t.version.empty() ? std::string() : (std::string(" version ") + t.version)) +
                          " on this host. Category: " + t.category + ".";
        iss.remediation = "Confirm that the disclosed version is up to date and that exposing the technology stack is acceptable for this surface.";
        issue_store::add(std::move(iss));
    }
    diag::log_tagged_fmt("tech_fp", "handle_exchange done host=%s new_issues=%zu", e.host.c_str(), new_to_emit.size());
}

bool regex_search_safe(const std::string& src, const std::string& pattern, std::smatch& m, bool case_insensitive)
{
    if (pattern.empty() || src.empty()) return false;
    try {
        auto flags = std::regex::ECMAScript;
        if (case_insensitive) flags = static_cast<std::regex::flag_type>(flags | std::regex::icase);
        std::regex re(pattern, flags);
        return std::regex_search(src, m, re);
    } catch (...) {
        return false;
    }
}

bool regex_search_safe(const std::string& src, const std::string& pattern, bool case_insensitive)
{
    if (pattern.empty() || src.empty()) return false;
    try {
        auto flags = std::regex::ECMAScript;
        if (case_insensitive) flags = static_cast<std::regex::flag_type>(flags | std::regex::icase);
        std::regex re(pattern, flags);
        return std::regex_search(src, re);
    } catch (...) {
        return false;
    }
}

}

bool initialize()
{
    diag::log_tagged_fmt("tech_fp", "initialize entry");
    bool expected = false;
    if (!initialized_flag().compare_exchange_strong(expected, true)) {
        diag::log_tagged_fmt("tech_fp", "initialize already_initialized");
        return true;
    }
    subscription_handle() = aida::events::subscribe(kExchangeObservedEvent, [](const exchange_observed_t& e) {
        handle_exchange(e);
    });
    diag::log_tagged("burp_tech", "initialized");
    diag::log_tagged_fmt("tech_fp", "initialize done rules=%zu", static_cast<size_t>(sizeof(kRules) / sizeof(kRules[0])));
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("tech_fp", "shutdown entry");
    if (!initialized_flag().exchange(false)) {
        diag::log_tagged_fmt("tech_fp", "shutdown not_initialized skipping");
        return;
    }
    aida::events::unsubscribe(subscription_handle());
    subscription_handle() = aida::events::subscription_handle_t{};
    std::lock_guard<std::mutex> lk(inv().mtx);
    size_t hosts = inv().by_host.size();
    size_t pairs = inv().issued_pairs.size();
    inv().by_host.clear();
    inv().issued_pairs.clear();
    diag::log_tagged_fmt("tech_fp", "shutdown done cleared hosts=%zu issued_pairs=%zu", hosts, pairs);
}

std::vector<tech_t> fingerprint(const std::vector<std::pair<std::string, std::string>>& response_headers,
                                const std::vector<uint8_t>& response_body,
                                const std::string& url)
{
    diag::log_tagged_fmt("tech_fp", "fingerprint entry url=%s headers=%zu body_bytes=%zu",
        url.c_str(), response_headers.size(), response_body.size());
    (void)url;
    std::vector<tech_t> out;
    std::string body_view;
    if (!response_body.empty()) {
        size_t n = std::min<size_t>(response_body.size(), 1024 * 1024);
        body_view.assign(reinterpret_cast<const char*>(response_body.data()), n);
        diag::log_tagged_fmt("tech_fp", "fingerprint body_view_size=%zu (capped from %zu)", n, response_body.size());
    }

    for (const auto& r : kRules) {
        bool header_hit = false;
        bool body_hit = false;
        std::string version;
        if (r.header_name && r.header_regex) {
            std::string hv = header_get(response_headers, r.header_name);
            if (!hv.empty()) {
                std::smatch m;
                if (regex_search_safe(hv, r.header_regex, m, true)) {
                    header_hit = true;
                    diag::log_tagged_fmt("tech_fp", "fingerprint header_hit rule=%s header=%s val=%s",
                        r.name, r.header_name, hv.c_str());
                    if (r.version_source && std::string(r.version_source) == "header" && r.version_regex) {
                        std::smatch vm;
                        if (regex_search_safe(hv, r.version_regex, vm, true) && vm.size() > 1) {
                            version = vm[1].str();
                            diag::log_tagged_fmt("tech_fp", "fingerprint version_extracted rule=%s ver=%s",
                                r.name, version.c_str());
                        }
                    }
                }
            }
        }
        if (!header_hit && r.body_regex && !body_view.empty()) {
            std::smatch m;
            if (regex_search_safe(body_view, r.body_regex, m, true)) {
                body_hit = true;
                diag::log_tagged_fmt("tech_fp", "fingerprint body_hit rule=%s", r.name);
                if (r.version_source && std::string(r.version_source) == "body" && r.version_regex) {
                    std::smatch vm;
                    if (regex_search_safe(body_view, r.version_regex, vm, true) && vm.size() > 1) {
                        version = vm[1].str();
                        diag::log_tagged_fmt("tech_fp", "fingerprint version_extracted_body rule=%s ver=%s",
                            r.name, version.c_str());
                    }
                }
            }
        }
        if (header_hit || body_hit) {
            tech_t t;
            t.name = r.name;
            t.category = r.category;
            t.version = version;
            t.confidence_label = header_hit ? "header" : "body";
            out.push_back(t);
        }
    }

    std::unordered_map<std::string, size_t> seen_per_cat;
    std::vector<tech_t> deduped;
    for (auto& t : out) {
        std::string key = t.name + "|" + t.category;
        if (seen_per_cat.count(key)) {
            diag::log_tagged_fmt("tech_fp", "fingerprint dedup_skip name=%s", t.name.c_str());
            continue;
        }
        seen_per_cat[key] = 1;
        deduped.push_back(std::move(t));
    }
    diag::log_tagged_fmt("tech_fp", "fingerprint done raw=%zu deduped=%zu", out.size(), deduped.size());
    return deduped;
}

std::vector<host_inventory_t> inventory()
{
    diag::log_tagged_fmt("tech_fp", "inventory entry");
    auto& s = inv();
    std::vector<host_inventory_t> out;
    std::lock_guard<std::mutex> lk(s.mtx);
    out.reserve(s.by_host.size());
    for (const auto& p : s.by_host) {
        host_inventory_t h;
        h.host = p.first;
        for (const auto& kv : p.second) h.technologies.push_back(kv.second);
        out.push_back(std::move(h));
    }
    diag::log_tagged_fmt("tech_fp", "inventory result hosts=%zu", out.size());
    return out;
}

void clear_inventory()
{
    diag::log_tagged_fmt("tech_fp", "clear_inventory entry");
    auto& s = inv();
    std::lock_guard<std::mutex> lk(s.mtx);
    size_t hosts = s.by_host.size();
    size_t pairs = s.issued_pairs.size();
    s.by_host.clear();
    s.issued_pairs.clear();
    diag::log_tagged_fmt("tech_fp", "clear_inventory done cleared hosts=%zu pairs=%zu", hosts, pairs);
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    std::string e = err_slot();
    diag::log_tagged_fmt("tech_fp", "last_error queried val=%s", e.c_str());
    return e;
}

}
}
}
