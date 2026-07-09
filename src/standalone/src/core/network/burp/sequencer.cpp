#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "sequencer.hpp"
#include "audit_http.hpp"
#include "../../infra/executor.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <regex>
#include <string>
#include <unordered_map>
#include <vector>
#include <utility>

namespace aida {
namespace burp {
namespace sequencer {

namespace {

struct collection_t
{
    uint64_t                  id = 0;
    collection_config_t       config;
    std::string               name;
    std::atomic<bool>         running{false};
    std::atomic<bool>         stop_request{false};
    std::atomic<bool>         error_flag{false};
    std::atomic<size_t>       collected{0};
    std::mutex                samples_mtx;
    std::vector<std::string>  samples;
    std::mutex                err_mtx;
    std::string               error_message;
    uint64_t                  started_ms = 0;
    std::atomic<uint64_t>     last_sample_ms{0};
    std::atomic<size_t>       in_flight{0};
    std::atomic<size_t>       consecutive_failures{0};
};

struct registry_t
{
    std::mutex                                                mtx;
    std::atomic<uint64_t>                                     next_id{1};
    std::unordered_map<uint64_t, std::shared_ptr<collection_t>> collections;
    std::mutex                                                err_mtx;
    std::string                                               last_err;
};

static registry_t g_reg;

static void set_last_error(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(g_reg.err_mtx);
    g_reg.last_err = msg;
}

static uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

static std::string extract_path(const std::string& url)
{
    if (url.rfind("http://", 0) == 0 || url.rfind("https://", 0) == 0) {
        size_t scheme_end = url.find("://");
        size_t path_start = url.find('/', scheme_end + 3);
        if (path_start == std::string::npos) return "/";
        return url.substr(path_start);
    }
    if (!url.empty() && url[0] == '/') return url;
    return "/" + url;
}

static std::vector<uint8_t> build_default_request(const std::string& host, uint16_t port, bool tls, const std::string& path)
{
    std::string authority = host;
    const bool default_port = (tls && port == 443) || (!tls && port == 80);
    if (!default_port) {
        authority += ":";
        authority += std::to_string(static_cast<unsigned>(port));
    }
    std::string req;
    req.reserve(path.size() + authority.size() + 96);
    req += "GET ";
    req += path.empty() ? "/" : path;
    req += " HTTP/1.1\r\nHost: ";
    req += authority;
    req += "\r\nUser-Agent: AiDA-Sequencer\r\nConnection: close\r\n\r\n";
    return std::vector<uint8_t>(req.begin(), req.end());
}

static size_t prune_empty_failed_collections_locked(uint64_t now, uint64_t min_age_ms)
{
    size_t pruned = 0;
    for (auto it = g_reg.collections.begin(); it != g_reg.collections.end(); ) {
        const auto& coll = it->second;
        const uint64_t started = coll ? coll->started_ms : 0;
        const uint64_t age = now >= started ? now - started : 0;
        const bool stale_failed_empty =
            coll &&
            coll->error_flag.load() &&
            !coll->running.load() &&
            coll->in_flight.load() == 0 &&
            coll->collected.load() == 0 &&
            coll->last_sample_ms.load() == 0 &&
            age >= min_age_ms;
        if (stale_failed_empty) {
            diag::log_tagged_fmt("sequencer", "prune_empty_failed_collection id=%llu age_ms=%llu",
                static_cast<unsigned long long>(coll->id),
                static_cast<unsigned long long>(age));
            it = g_reg.collections.erase(it);
            ++pruned;
        } else {
            ++it;
        }
    }
    return pruned;
}

static bool perform_one_request(const collection_config_t& cfg, const std::regex& re, std::string& out_token, std::string& out_err)
{
    diag::log_tagged_fmt("sequencer", "perform_one_request entry host=%s port=%u tls=%d url=%s",
        cfg.host.c_str(), (unsigned)cfg.port, (int)cfg.use_tls, cfg.url.c_str());
    std::string scheme;
    std::string host = cfg.host;
    uint16_t port = cfg.port;
    bool tls = cfg.use_tls;
    std::string path = cfg.url.empty() ? "/" : extract_path(cfg.url);
    if (!cfg.url.empty() && (cfg.url.rfind("http://", 0) == 0 || cfg.url.rfind("https://", 0) == 0)) {
        if (!aida::burp::audit_http::parse_url(cfg.url, scheme, host, port, path)) {
            out_err = "url_parse_failed";
            diag::log_tagged_fmt("sequencer", "perform_one_request error url_parse_failed url=%s", cfg.url.c_str());
            return false;
        }
        tls = (scheme == "https");
    }
    if (host.empty()) {
        out_err = "host_empty";
        diag::log_tagged_fmt("sequencer", "perform_one_request error host_empty url=%s", cfg.url.c_str());
        return false;
    }
    std::vector<uint8_t> request = cfg.raw_request.empty() ? build_default_request(host, port, tls, path) : cfg.raw_request;
    aida::burp::audit_http::send_options_t options;
    options.timeout_ms = 3000;
    options.follow_redirects = true;
    options.max_redirects = 3;
    options.enforce_scope = false;
    auto exchange = aida::burp::audit_http::send(request, host, port, tls, options);
    if (!exchange) {
        const std::string detail = aida::burp::audit_http::last_error();
        out_err = detail.empty() ? "transport_error" : "transport_error:" + detail;
        diag::log_tagged_fmt("sequencer", "perform_one_request error transport_error host=%s port=%u tls=%d path=%s detail=%s",
            host.c_str(), static_cast<unsigned>(port), tls ? 1 : 0, path.c_str(), detail.c_str());
        return false;
    }

    std::string body(exchange->resp_body.begin(), exchange->resp_body.end());
    diag::log_tagged_fmt("sequencer", "perform_one_request http_ok host=%s port=%u tls=%d status=%d body_len=%zu latency_ms=%llu",
        host.c_str(), static_cast<unsigned>(port), tls ? 1 : 0, exchange->status_code, body.size(),
        static_cast<unsigned long long>(exchange->latency_ms));

    std::smatch m;
    if (!std::regex_search(body, m, re)) {
        std::string composite;
        for (const auto& h : exchange->resp_headers) {
            composite += h.first;
            composite += ": ";
            composite += h.second;
            composite += "\n";
        }
        if (std::regex_search(composite, m, re)) {
            diag::log_tagged_fmt("sequencer", "perform_one_request extracted_from_headers");
        } else {
            diag::log_tagged_fmt("sequencer", "perform_one_request error extraction_miss host=%s port=%u path=%s status=%d",
                host.c_str(), static_cast<unsigned>(port), path.c_str(), exchange->status_code);
            out_err = "extraction_miss";
            return false;
        }
    }

    int group = cfg.capture_group;
    if (group < 0) group = 0;
    if (m.size() > 1) {
        if (static_cast<size_t>(group) < m.size()) {
            out_token = m[group].str();
            diag::log_tagged_fmt("sequencer", "perform_one_request extracted token_len=%zu group=%d", out_token.size(), group);
            return true;
        }
        out_token = m[0].str();
        diag::log_tagged_fmt("sequencer", "perform_one_request extracted token_len=%zu fallback_group=0", out_token.size());
        return true;
    }
    out_token = m[0].str();
    diag::log_tagged_fmt("sequencer", "perform_one_request extracted token_len=%zu", out_token.size());
    return true;
}

static void collection_worker(std::shared_ptr<collection_t> coll)
{
    if (!coll) return;
    std::regex re;
    try {
        re = std::regex(coll->config.extract_regex, std::regex::ECMAScript | std::regex::optimize);
    } catch (...) {
        {
            std::lock_guard<std::mutex> lk(coll->err_mtx);
            coll->error_message = "invalid_regex";
        }
        coll->error_flag.store(true);
        set_last_error("invalid_regex");
        coll->running.store(false);
        ::diag::log_tagged_fmt("sequencer", "collection_failed id=%llu reason=invalid_regex",
            static_cast<unsigned long long>(coll->id));
        return;
    }

    coll->started_ms = now_ms();

    size_t total_attempts = 0;
    size_t max_attempts = coll->config.target_count * 4 + 64;
    while (coll->running.load() && !coll->stop_request.load()) {
        if (coll->collected.load() >= coll->config.target_count) break;
        if (coll->consecutive_failures.load() >= 32) {
            {
                std::lock_guard<std::mutex> lk(coll->err_mtx);
                if (coll->error_message.empty()) coll->error_message = "too_many_failures";
            }
            coll->error_flag.store(true);
            break;
        }
        if (total_attempts >= max_attempts) {
            {
                std::lock_guard<std::mutex> lk(coll->err_mtx);
                if (coll->error_message.empty()) coll->error_message = "attempt_cap_reached";
            }
            coll->error_flag.store(true);
            break;
        }

        if (coll->in_flight.load() >= coll->config.concurrency) {
            Sleep(5);
            continue;
        }

        if (coll->config.throttle_ms > 0) {
            Sleep(static_cast<DWORD>(coll->config.throttle_ms));
        }

        coll->in_flight.fetch_add(1);
        total_attempts++;
        collection_config_t cfg_snapshot = coll->config;
        std::shared_ptr<collection_t> coll_ref = coll;
        std::regex re_copy = re;
        auto sample_task = [coll_ref, cfg_snapshot, re_copy]() {
            std::string token;
            std::string err;
            bool ok = perform_one_request(cfg_snapshot, re_copy, token, err);
            if (ok && !token.empty()) {
                std::lock_guard<std::mutex> lk(coll_ref->samples_mtx);
                coll_ref->samples.push_back(token);
                coll_ref->collected.store(coll_ref->samples.size());
                coll_ref->last_sample_ms.store(now_ms());
                coll_ref->consecutive_failures.store(0);
            } else {
                coll_ref->consecutive_failures.fetch_add(1);
                if (!ok) {
                    std::lock_guard<std::mutex> lk(coll_ref->err_mtx);
                    if (coll_ref->error_message.empty()) coll_ref->error_message = err;
                }
                if (!err.empty()) set_last_error(err);
            }
            coll_ref->in_flight.fetch_sub(1);
        };
        bool posted = false;
        try {
            posted = [&]() {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.sequencer";
                sub.label = "sequencer.sample";
                sub.thread_class = "bounded_task";
                sub.domain = aida::infra::executor::domain_t::external_tool;
                sub.priority = 3;
                sub.body = sample_task;
                return ::aida::infra::executor::submit(std::move(sub)).submitted;
            }();
        } catch (...) {
            posted = false;
        }
        if (!posted) {
            diag::log_tagged_fmt("sequencer", "collection_sample_post_failed id=%llu attempt=%zu in_flight=%zu",
                static_cast<unsigned long long>(coll->id),
                total_attempts,
                coll->in_flight.load());
            {
                std::lock_guard<std::mutex> lk(coll->err_mtx);
                if (coll->error_message.empty()) coll->error_message = "sample_executor_post_failed";
            }
            coll->error_flag.store(true);
            coll->in_flight.fetch_sub(1);
        }
    }

    while (coll->in_flight.load() > 0) {
        Sleep(20);
    }

    if (coll->error_flag.load()) {
        std::string err;
        {
            std::lock_guard<std::mutex> lk(coll->err_mtx);
            err = coll->error_message;
        }
        if (!err.empty()) set_last_error(err);
    }
    coll->running.store(false);
    ::diag::log_tagged_fmt("sequencer", "collection_done id=%llu collected=%zu target=%zu",
        static_cast<unsigned long long>(coll->id),
        coll->samples.size(), coll->config.target_count);
}

static std::vector<uint8_t> tokens_to_bitstream(const std::vector<std::string>& tokens)
{
    std::vector<uint8_t> out;
    size_t total_bytes = 0;
    for (const auto& t : tokens) total_bytes += t.size();
    out.reserve(total_bytes);
    for (const auto& t : tokens) {
        for (char c : t) out.push_back(static_cast<uint8_t>(c));
    }
    return out;
}

static double regularized_gamma_q(double s, double x)
{
    if (x < 0.0 || s <= 0.0) return 1.0;
    if (x == 0.0) return 1.0;
    if (x < s + 1.0) {
        double ap = s;
        double sum = 1.0 / s;
        double del = sum;
        for (int n = 1; n <= 200; ++n) {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if (std::fabs(del) < std::fabs(sum) * 1e-12) break;
        }
        double gln = std::lgamma(s);
        double g = sum * std::exp(-x + s * std::log(x) - gln);
        return 1.0 - g;
    } else {
        double b = x + 1.0 - s;
        double c = 1.0 / 1e-300;
        double d = 1.0 / b;
        double h = d;
        for (int i = 1; i <= 200; ++i) {
            double an = -static_cast<double>(i) * (static_cast<double>(i) - s);
            b += 2.0;
            d = an * d + b;
            if (std::fabs(d) < 1e-300) d = 1e-300;
            c = b + an / c;
            if (std::fabs(c) < 1e-300) c = 1e-300;
            d = 1.0 / d;
            double del = d * c;
            h *= del;
            if (std::fabs(del - 1.0) < 1e-12) break;
        }
        double gln = std::lgamma(s);
        return std::exp(-x + s * std::log(x) - gln) * h;
    }
}

static double erfc_approx(double x)
{
    double z = std::fabs(x);
    double t = 1.0 / (1.0 + 0.5 * z);
    double r = t * std::exp(-z * z - 1.26551223 +
                            t * (1.00002368 +
                            t * (0.37409196 +
                            t * (0.09678418 +
                            t * (-0.18628806 +
                            t * (0.27886807 +
                            t * (-1.13520398 +
                            t * (1.48851587 +
                            t * (-0.82215223 +
                            t * 0.17087277))))))) ));
    return x >= 0.0 ? r : (2.0 - r);
}

static std::string normalize_mode(std::string mode)
{
    std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (mode == "bit" || mode == "bits") return "bit";
    if (mode == "byte" || mode == "bytes") return "byte";
    if (mode == "character" || mode == "characters" || mode == "char") return "character";
    if (mode == "position" || mode == "positions") return "position";
    return "all";
}

static analysis_result_t analyze_internal(const std::vector<std::string>& tokens, const analysis_config_t& config)
{
    analysis_result_t a;
    a.analysis_mode = normalize_mode(config.mode);
    if (tokens.empty()) {
        a.verdict = "no_samples";
        a.confidence_label = "none";
        a.fips_assessment = "not_evaluated_no_samples";
        a.nist_sp800_90b_assessment = "not_evaluated_no_samples";
        return a;
    }
    a.samples_count = tokens.size();

    std::unordered_map<size_t, size_t> length_hist;
    a.min_token_length = tokens.front().size();
    a.max_token_length = tokens.front().size();
    for (const auto& t : tokens) {
        length_hist[t.size()]++;
        a.min_token_length = (std::min)(a.min_token_length, t.size());
        a.max_token_length = (std::max)(a.max_token_length, t.size());
    }
    size_t mode_len = 0;
    size_t mode_count = 0;
    for (const auto& kv : length_hist) {
        if (kv.second > mode_count) { mode_count = kv.second; mode_len = kv.first; }
    }
    a.token_length_mode = mode_len;

    std::vector<uint8_t> bytes = tokens_to_bitstream(tokens);
    a.total_bits = bytes.size() * 8;
    if (bytes.empty()) {
        a.verdict = "empty_tokens";
        return a;
    }

    for (uint8_t b : bytes) a.byte_frequency[b]++;
    double n = static_cast<double>(bytes.size());
    size_t max_frequency = 0;
    for (size_t i = 0; i < 256; ++i) {
        if (a.byte_frequency[i] != 0) {
            ++a.alphabet_size;
            max_frequency = (std::max)(max_frequency, a.byte_frequency[i]);
        }
    }

    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (a.byte_frequency[i] == 0) continue;
        double p = static_cast<double>(a.byte_frequency[i]) / n;
        entropy -= p * (std::log(p) / std::log(2.0));
    }
    a.shannon_entropy_bits = entropy;
    if (max_frequency > 0 && n > 0.0) {
        const double pmax = static_cast<double>(max_frequency) / n;
        a.min_entropy_bits_per_symbol = -std::log(pmax) / std::log(2.0);
    }

    double expected = n / 256.0;
    double chi = 0.0;
    if (expected > 0.0) {
        for (size_t i = 0; i < 256; ++i) {
            double diff = static_cast<double>(a.byte_frequency[i]) - expected;
            chi += diff * diff / expected;
        }
    }
    a.chi_square = chi;
    if (n >= 50.0) {
        a.chi_square_p_value = regularized_gamma_q(255.0 / 2.0, chi / 2.0);
    } else {
        a.chi_square_p_value = std::nan("");
    }

    const size_t configured_positions = config.max_positions == 0 ? 128 : config.max_positions;
    const size_t position_cap = (std::min)((std::min)(configured_positions, static_cast<size_t>(256)), a.max_token_length);
    a.position_analysis.reserve(position_cap);
    for (size_t i = 0; i < position_cap; ++i) {
        size_t accum = 0;
        size_t count = 0;
        std::vector<size_t> counts(256, 0);
        for (const auto& t : tokens) {
            if (i < t.size()) {
                const uint8_t c = static_cast<uint8_t>(t[i]);
                accum += c;
                ++count;
                counts[c]++;
            }
        }
        a.position_bias[i] = count > 0 ? (static_cast<double>(accum) / static_cast<double>(count)) - 127.5 : 0.0;
        position_stat_t ps;
        ps.index = i;
        ps.samples = count;
        double expected_pos = count > 0 ? static_cast<double>(count) / 256.0 : 0.0;
        for (size_t c = 0; c < counts.size(); ++c) {
            const size_t value = counts[c];
            if (value == 0) continue;
            ++ps.distinct_symbols;
            if (value > ps.most_common_count) {
                ps.most_common_count = value;
                ps.most_common_symbol = static_cast<uint8_t>(c);
            }
            const double p = static_cast<double>(value) / static_cast<double>(count);
            ps.entropy_bits -= p * (std::log(p) / std::log(2.0));
            if (expected_pos > 0.0) {
                const double diff = static_cast<double>(value) - expected_pos;
                ps.chi_square += diff * diff / expected_pos;
            }
        }
        ps.most_common_frequency = count > 0 ? static_cast<double>(ps.most_common_count) / static_cast<double>(count) : 0.0;
        ps.chi_square_p_value = count >= 50 ? regularized_gamma_q(255.0 / 2.0, ps.chi_square / 2.0) : std::nan("");
        a.position_analysis.push_back(ps);
    }

    size_t total_bits = a.total_bits;
    size_t ones = 0;
    for (uint8_t b : bytes) {
        for (int j = 0; j < 8; ++j) if ((b >> j) & 1) ones++;
    }
    a.monobit_ones = ones;
    a.monobit_zeros = (total_bits >= ones) ? (total_bits - ones) : 0;

    if (total_bits >= 100) {
        double s_n = (static_cast<double>(ones) - static_cast<double>(a.monobit_zeros)) /
                     std::sqrt(static_cast<double>(total_bits));
        double s_obs = std::fabs(s_n) / std::sqrt(2.0);
        a.monobit_p_value = erfc_approx(s_obs);
    } else {
        a.monobit_p_value = std::nan("");
    }

    if (total_bits >= 100) {
        size_t m = 4;
        size_t M = total_bits / m;
        if (M > 0) {
            std::vector<size_t> counts(16, 0);
            for (size_t i = 0; i < M; ++i) {
                size_t v = 0;
                for (size_t j = 0; j < m; ++j) {
                    size_t bit_idx = i * m + j;
                    size_t byte_idx = bit_idx / 8;
                    size_t bit_in_byte = bit_idx % 8;
                    uint8_t bit = (bytes[byte_idx] >> bit_in_byte) & 1;
                    v = (v << 1) | bit;
                }
                counts[v]++;
            }
            double sum = 0.0;
            for (auto c : counts) sum += static_cast<double>(c) * static_cast<double>(c);
            double poker = (16.0 * sum / static_cast<double>(M)) - static_cast<double>(M);
            a.poker_p_value = regularized_gamma_q(15.0 / 2.0, poker / 2.0);
        } else {
            a.poker_p_value = std::nan("");
        }
    } else {
        a.poker_p_value = std::nan("");
    }

    if (total_bits >= 100) {
        double pi = static_cast<double>(ones) / static_cast<double>(total_bits);
        if (std::fabs(pi - 0.5) < (2.0 / std::sqrt(static_cast<double>(total_bits)))) {
            size_t vobs = 1;
            uint8_t prev_bit = bytes[0] & 1;
            for (size_t bit_idx = 1; bit_idx < total_bits; ++bit_idx) {
                size_t byte_idx = bit_idx / 8;
                size_t bit_in_byte = bit_idx % 8;
                uint8_t b = (bytes[byte_idx] >> bit_in_byte) & 1;
                if (b != prev_bit) vobs++;
                prev_bit = b;
            }
            double num = std::fabs(static_cast<double>(vobs) - 2.0 * static_cast<double>(total_bits) * pi * (1.0 - pi));
            double den = 2.0 * std::sqrt(2.0 * static_cast<double>(total_bits)) * pi * (1.0 - pi);
            if (den > 0.0) a.runs_p_value = erfc_approx(num / den);
            else a.runs_p_value = std::nan("");
        } else {
            a.runs_p_value = 0.0;
        }
    } else {
        a.runs_p_value = std::nan("");
    }

    if (total_bits >= 128) {
        size_t M = 8;
        size_t N = total_bits / M;
        if (N >= 16) {
            std::vector<size_t> hist_v(4, 0);
            for (size_t i = 0; i < N; ++i) {
                size_t max_run = 0, cur = 0;
                for (size_t j = 0; j < M; ++j) {
                    size_t bit_idx = i * M + j;
                    size_t byte_idx = bit_idx / 8;
                    size_t bit_in_byte = bit_idx % 8;
                    uint8_t b = (bytes[byte_idx] >> bit_in_byte) & 1;
                    if (b) { cur++; if (cur > max_run) max_run = cur; }
                    else cur = 0;
                }
                size_t bucket = 0;
                if (max_run <= 1) bucket = 0;
                else if (max_run == 2) bucket = 1;
                else if (max_run == 3) bucket = 2;
                else bucket = 3;
                hist_v[bucket]++;
            }
            double pi_arr[4] = { 0.2148, 0.3672, 0.2305, 0.1875 };
            double chi_lr = 0.0;
            for (int i = 0; i < 4; ++i) {
                double expected_i = static_cast<double>(N) * pi_arr[i];
                if (expected_i > 0.0) {
                    double diff = static_cast<double>(hist_v[i]) - expected_i;
                    chi_lr += diff * diff / expected_i;
                }
            }
            a.long_run_p_value = regularized_gamma_q(3.0 / 2.0, chi_lr / 2.0);
        } else {
            a.long_run_p_value = std::nan("");
        }
    } else {
        a.long_run_p_value = std::nan("");
    }

    if (total_bits >= 1010) {
        size_t L = 6;
        size_t Q = 640;
        size_t K = total_bits / L;
        if (K > Q + 16) {
            K -= Q;
            std::vector<size_t> T(size_t{1} << L, 0);
            for (size_t i = 1; i <= Q; ++i) {
                size_t v = 0;
                for (size_t j = 0; j < L; ++j) {
                    size_t bit_idx = (i - 1) * L + j;
                    size_t byte_idx = bit_idx / 8;
                    size_t bit_in_byte = bit_idx % 8;
                    uint8_t b = (bytes[byte_idx] >> bit_in_byte) & 1;
                    v = (v << 1) | b;
                }
                T[v] = i;
            }
            double sum_log = 0.0;
            for (size_t i = Q + 1; i <= Q + K; ++i) {
                size_t v = 0;
                for (size_t j = 0; j < L; ++j) {
                    size_t bit_idx = (i - 1) * L + j;
                    size_t byte_idx = bit_idx / 8;
                    size_t bit_in_byte = bit_idx % 8;
                    uint8_t b = (bytes[byte_idx] >> bit_in_byte) & 1;
                    v = (v << 1) | b;
                }
                size_t distance = i - T[v];
                if (distance > 0) sum_log += std::log(static_cast<double>(distance)) / std::log(2.0);
                T[v] = i;
            }
            a.maurer_universal = sum_log / static_cast<double>(K);
        } else {
            a.maurer_universal = std::nan("");
        }
    } else {
        a.maurer_universal = std::nan("");
    }

    if (total_bits >= 2) {
        size_t matches = 0;
        size_t pairs = total_bits - 1;
        uint8_t prev = bytes[0] & 1;
        for (size_t bit_idx = 1; bit_idx < total_bits; ++bit_idx) {
            size_t byte_idx = bit_idx / 8;
            size_t bit_in_byte = bit_idx % 8;
            uint8_t b = (bytes[byte_idx] >> bit_in_byte) & 1;
            if (b == prev) matches++;
            prev = b;
        }
        a.autocorrelation = (static_cast<double>(matches) / static_cast<double>(pairs)) - 0.5;
    } else {
        a.autocorrelation = std::nan("");
    }

    if (bytes.size() >= 2) {
        double sx = 0.0;
        double sy = 0.0;
        const size_t pairs = bytes.size() - 1;
        for (size_t i = 0; i < pairs; ++i) {
            sx += static_cast<double>(bytes[i]);
            sy += static_cast<double>(bytes[i + 1]);
        }
        const double mx = sx / static_cast<double>(pairs);
        const double my = sy / static_cast<double>(pairs);
        double num = 0.0;
        double dx = 0.0;
        double dy = 0.0;
        for (size_t i = 0; i < pairs; ++i) {
            const double x = static_cast<double>(bytes[i]) - mx;
            const double y = static_cast<double>(bytes[i + 1]) - my;
            num += x * y;
            dx += x * x;
            dy += y * y;
        }
        a.serial_correlation = (dx > 0.0 && dy > 0.0) ? num / std::sqrt(dx * dy) : 0.0;
        size_t runs = 1;
        for (size_t i = 1; i < bytes.size(); ++i) {
            if (bytes[i] != bytes[i - 1]) ++runs;
        }
        a.compression_ratio = static_cast<double>(runs) / static_cast<double>(bytes.size());
    } else {
        a.serial_correlation = std::nan("");
        a.compression_ratio = 1.0;
    }

    bool fips_ok = false;
    if (total_bits >= 20000) {
        bool monobit_ok = (ones >= 9725 && ones <= 10275);
        bool poker_ok = (a.poker_p_value > 0.0001 && a.poker_p_value < 0.9999);
        bool runs_ok = (a.runs_p_value > 0.0001);
        bool long_run_ok = (a.long_run_p_value > 0.0001);
        fips_ok = monobit_ok && poker_ok && runs_ok && long_run_ok;
    }
    a.passes_fips_140_2 = fips_ok;
    if (total_bits < 20000) {
        a.fips_assessment = "legacy_fips_140_2_style_not_enough_bits";
    } else {
        a.fips_assessment = fips_ok ? "legacy_fips_140_2_style_pass" : "legacy_fips_140_2_style_fail";
    }
    if (a.samples_count < 100 || bytes.size() < 100) {
        a.nist_sp800_90b_assessment = "sp800_90b_informational_estimators_insufficient_sample";
    } else if (a.min_entropy_bits_per_symbol >= 6.0 && std::fabs(a.serial_correlation) < 0.15) {
        a.nist_sp800_90b_assessment = "sp800_90b_informational_estimators_strong";
    } else if (a.min_entropy_bits_per_symbol >= 4.0 && std::fabs(a.serial_correlation) < 0.30) {
        a.nist_sp800_90b_assessment = "sp800_90b_informational_estimators_moderate";
    } else {
        a.nist_sp800_90b_assessment = "sp800_90b_informational_estimators_weak";
    }
    a.valid = true;

    double score = 0.0;
    int counted = 0;
    if (!std::isnan(a.monobit_p_value))   { score += a.monobit_p_value;   ++counted; }
    if (!std::isnan(a.poker_p_value))     { score += a.poker_p_value;     ++counted; }
    if (!std::isnan(a.runs_p_value))      { score += a.runs_p_value;      ++counted; }
    if (!std::isnan(a.long_run_p_value))  { score += a.long_run_p_value;  ++counted; }
    if (!std::isnan(a.chi_square_p_value)){ score += a.chi_square_p_value;++counted; }
    double avg = counted > 0 ? score / counted : 0.0;
    const double sample_factor = (std::min)(1.0, static_cast<double>(a.samples_count) / 200.0);
    const double entropy_factor = (std::min)(1.0, a.min_entropy_bits_per_symbol / 6.0);
    const double correlation_factor = std::isnan(a.serial_correlation) ? 0.5 : (std::max)(0.0, 1.0 - std::fabs(a.serial_correlation));
    a.confidence_score = (std::max)(0.0, (std::min)(1.0, (avg * 0.50) + (sample_factor * 0.25) + (entropy_factor * 0.15) + (correlation_factor * 0.10)));
    if (a.samples_count < 50) a.confidence_label = "low_sample";
    else if (a.confidence_score >= 0.75) a.confidence_label = "high";
    else if (a.confidence_score >= 0.45) a.confidence_label = "medium";
    else a.confidence_label = "low";

    if (a.samples_count < 50) {
        a.verdict = "Inconclusive (sample too small, collect >=200 for FIPS verdict)";
    } else if (a.samples_count < 200) {
        a.verdict = avg > 0.05 ? "Adequate (limited sample)" : "Poor (limited sample)";
    } else if (avg > 0.20 && fips_ok)     a.verdict = "Excellent";
    else if (avg > 0.05 && fips_ok)       a.verdict = "Good";
    else if (avg > 0.01)                  a.verdict = "Adequate";
    else                                  a.verdict = "Poor";
    a.notes = "FIPS output is a legacy 140-2-style compatibility assessment over collected bits, not a FIPS validation. NIST SP 800-90B output uses local most-common-value, entropy, and serial-correlation estimators and is informational, not a full SP 800-90B validation.";

    return a;
}

}

uint64_t start_collection(const collection_config_t& cfg)
{
    if (cfg.extract_regex.empty()) {
        set_last_error("extract_regex_required");
        return 0;
    }
    if (cfg.url.empty() && cfg.host.empty()) {
        set_last_error("url_or_host_required");
        return 0;
    }
    if (cfg.target_count == 0) {
        set_last_error("target_count_zero");
        return 0;
    }

    auto coll = std::make_shared<collection_t>();
    coll->id = g_reg.next_id.fetch_add(1);
    coll->config = cfg;
    coll->name = cfg.name.empty() ? cfg.url : cfg.name;
    coll->running.store(true);
    coll->started_ms = now_ms();
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        const size_t pruned = prune_empty_failed_collections_locked(coll->started_ms, 30000);
        if (pruned > 0) {
            ::diag::log_tagged_fmt("sequencer", "start_collection pruned_empty_failed=%zu new_id=%llu",
                pruned,
                static_cast<unsigned long long>(coll->id));
        }
        g_reg.collections[coll->id] = coll;
    }

    std::shared_ptr<collection_t> coll_ref = coll;
    bool posted = false;
    try {
        posted = [&]() {
            ::aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "burp.sequencer";
            sub.label = "sequencer.collection_worker";
            sub.thread_class = "long_running";
            sub.domain = aida::infra::executor::domain_t::long_running;
            sub.priority = 3;
            sub.body = [coll_ref]() {
            collection_worker(coll_ref);
        };
            return ::aida::infra::executor::submit(std::move(sub)).submitted;
        }();
    } catch (...) {
        posted = false;
    }
    if (!posted) {
        {
            std::lock_guard<std::mutex> lk(coll->err_mtx);
            coll->error_message = "collection_worker_executor_failed";
        }
        coll->error_flag.store(true);
        coll->running.store(false);
        set_last_error("collection_worker_executor_failed");
        ::diag::log_tagged_fmt("sequencer", "collection_worker_post_failed id=%llu url='%s'",
            static_cast<unsigned long long>(coll->id),
            cfg.url.c_str());
        {
            std::lock_guard<std::mutex> lk(g_reg.mtx);
            g_reg.collections.erase(coll->id);
        }
        return 0;
    }

    ::diag::log_tagged_fmt("sequencer", "collection_started id=%llu url='%s' target=%zu concurrency=%zu",
        static_cast<unsigned long long>(coll->id),
        cfg.url.c_str(), cfg.target_count, cfg.concurrency);

    return coll->id;
}

bool stop_collection(uint64_t id)
{
    std::shared_ptr<collection_t> coll;
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        auto it = g_reg.collections.find(id);
        if (it == g_reg.collections.end()) return false;
        coll = it->second;
    }
    coll->stop_request.store(true);
    coll->running.store(false);
    ::diag::log_tagged_fmt("sequencer", "collection_stop_requested id=%llu", static_cast<unsigned long long>(id));
    return true;
}

collection_status_t status(uint64_t id)
{
    diag::log_tagged_fmt("sequencer", "status entry id=%llu", static_cast<unsigned long long>(id));
    collection_status_t s;
    std::shared_ptr<collection_t> coll;
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        auto it = g_reg.collections.find(id);
        if (it == g_reg.collections.end()) {
            diag::log_tagged_fmt("sequencer", "status not_found id=%llu", static_cast<unsigned long long>(id));
            return s;
        }
        coll = it->second;
    }
    s.id = coll->id;
    s.url = coll->config.url;
    s.name = coll->name;
    s.collected = coll->collected.load();
    s.target = coll->config.target_count;
    s.running = coll->running.load();
    s.error = coll->error_flag.load();
    {
        std::lock_guard<std::mutex> lk(coll->err_mtx);
        s.error_message = coll->error_message;
    }
    s.started_ms = coll->started_ms;
    s.last_sample_ms = coll->last_sample_ms.load();
    diag::log_tagged_fmt("sequencer", "status id=%llu collected=%zu target=%zu running=%d error=%d",
        static_cast<unsigned long long>(id), s.collected, s.target, (int)s.running, (int)s.error);
    return s;
}

std::vector<std::string> samples(uint64_t id, size_t max_count)
{
    diag::log_tagged_fmt("sequencer", "samples entry id=%llu max_count=%zu", static_cast<unsigned long long>(id), max_count);
    std::shared_ptr<collection_t> coll;
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        auto it = g_reg.collections.find(id);
        if (it == g_reg.collections.end()) {
            diag::log_tagged_fmt("sequencer", "samples not_found id=%llu", static_cast<unsigned long long>(id));
            return {};
        }
        coll = it->second;
    }
    std::lock_guard<std::mutex> lk(coll->samples_mtx);
    size_t total = coll->samples.size();
    if (max_count == 0 || max_count >= total) {
        diag::log_tagged_fmt("sequencer", "samples result id=%llu count=%zu", static_cast<unsigned long long>(id), total);
        return coll->samples;
    }
    diag::log_tagged_fmt("sequencer", "samples result id=%llu count=%zu (capped)", static_cast<unsigned long long>(id), max_count);
    return std::vector<std::string>(coll->samples.end() - static_cast<ptrdiff_t>(max_count), coll->samples.end());
}

analysis_result_t analyze(uint64_t id)
{
    analysis_config_t cfg;
    return analyze(id, cfg);
}

analysis_result_t analyze(uint64_t id, const analysis_config_t& config)
{
    diag::log_tagged_fmt("sequencer", "analyze entry id=%llu", static_cast<unsigned long long>(id));
    std::shared_ptr<collection_t> coll;
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        auto it = g_reg.collections.find(id);
        if (it == g_reg.collections.end()) {
            diag::log_tagged_fmt("sequencer", "analyze error not_found id=%llu", static_cast<unsigned long long>(id));
            analysis_result_t a;
            a.verdict = "collection_not_found";
            return a;
        }
        coll = it->second;
    }
    std::vector<std::string> snap;
    {
        std::lock_guard<std::mutex> lk(coll->samples_mtx);
        snap = coll->samples;
    }
    diag::log_tagged_fmt("sequencer", "analyze analyzing id=%llu samples=%zu", static_cast<unsigned long long>(id), snap.size());
    analysis_result_t r = analyze_internal(snap, config);
    r.collection_id = id;
    diag::log_tagged_fmt("sequencer", "analyze done id=%llu mode=%s verdict='%s' samples=%zu entropy=%.3f confidence=%.3f",
        static_cast<unsigned long long>(id), r.analysis_mode.c_str(), r.verdict.c_str(), r.samples_count, r.shannon_entropy_bits, r.confidence_score);
    return r;
}

std::vector<collection_status_t> list_collections()
{
    diag::log_tagged_fmt("sequencer", "list_collections entry");
    std::vector<collection_status_t> out;
    std::vector<uint64_t> ids;
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        ids.reserve(g_reg.collections.size());
        for (const auto& kv : g_reg.collections) ids.push_back(kv.first);
    }
    out.reserve(ids.size());
    for (uint64_t id : ids) out.push_back(status(id));
    diag::log_tagged_fmt("sequencer", "list_collections result count=%zu", out.size());
    return out;
}

bool delete_collection(uint64_t id)
{
    diag::log_tagged_fmt("sequencer", "delete_collection entry id=%llu", static_cast<unsigned long long>(id));
    std::shared_ptr<collection_t> coll;
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        auto it = g_reg.collections.find(id);
        if (it == g_reg.collections.end()) {
            diag::log_tagged_fmt("sequencer", "delete_collection not_found id=%llu", static_cast<unsigned long long>(id));
            return false;
        }
        coll = it->second;
    }
    coll->stop_request.store(true);
    coll->running.store(false);
    diag::log_tagged_fmt("sequencer", "delete_collection waiting_inflight id=%llu in_flight=%zu",
        static_cast<unsigned long long>(id), coll->in_flight.load());
    while (coll->in_flight.load() > 0) Sleep(5);
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        g_reg.collections.erase(id);
    }
    diag::log_tagged_fmt("sequencer", "delete_collection ok id=%llu", static_cast<unsigned long long>(id));
    return true;
}

std::string last_error()
{
    diag::log_tagged_fmt("sequencer", "last_error queried");
    std::lock_guard<std::mutex> lk(g_reg.err_mtx);
    return g_reg.last_err;
}

}
}
}
