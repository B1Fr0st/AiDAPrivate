#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "sequencer.hpp"
#include "../../infra/work_queue.hpp"
#include "helpers/diag_log.hpp"

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#include "httplib.h"

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

static std::string make_origin(const std::string& url_or_origin, const std::string& host, uint16_t port, bool use_tls)
{
    if (!url_or_origin.empty()) {
        if (url_or_origin.rfind("http://", 0) == 0 || url_or_origin.rfind("https://", 0) == 0) {
            size_t scheme_end = url_or_origin.find("://");
            size_t path_start = url_or_origin.find('/', scheme_end + 3);
            if (path_start == std::string::npos) return url_or_origin;
            return url_or_origin.substr(0, path_start);
        }
    }
    std::string origin = (use_tls ? "https://" : "http://") + host;
    bool default_port = (use_tls && port == 443) || (!use_tls && port == 80);
    if (!default_port) origin += ":" + std::to_string(static_cast<int>(port));
    return origin;
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

static bool perform_one_request(const collection_config_t& cfg, const std::regex& re, std::string& out_token, std::string& out_err)
{
    std::string origin = make_origin(cfg.url, cfg.host, cfg.port, cfg.use_tls);
    std::string path = cfg.url.empty() ? "/" : extract_path(cfg.url);

    httplib::Client cli(origin);
    cli.set_connection_timeout(10);
    cli.set_read_timeout(20);
    cli.set_write_timeout(10);
    cli.enable_server_certificate_verification(false);
    cli.set_follow_location(true);

    httplib::Result res;
    if (!cfg.raw_request.empty()) {
        std::string method = "GET";
        for (size_t i = 0; i < cfg.raw_request.size() && i < 16; ++i) {
            char c = static_cast<char>(cfg.raw_request[i]);
            if (c == ' ') {
                method.assign(cfg.raw_request.begin(), cfg.raw_request.begin() + static_cast<ptrdiff_t>(i));
                break;
            }
        }
        std::string upper = method;
        for (auto& c : upper) c = static_cast<char>(::toupper(static_cast<unsigned char>(c)));

        std::string raw_body;
        size_t hdr_end = 0;
        for (size_t i = 0; i + 3 < cfg.raw_request.size(); ++i) {
            if (cfg.raw_request[i] == '\r' && cfg.raw_request[i + 1] == '\n' &&
                cfg.raw_request[i + 2] == '\r' && cfg.raw_request[i + 3] == '\n') {
                hdr_end = i + 4;
                break;
            }
        }
        if (hdr_end > 0 && hdr_end < cfg.raw_request.size()) {
            raw_body.assign(reinterpret_cast<const char*>(cfg.raw_request.data() + hdr_end),
                            cfg.raw_request.size() - hdr_end);
        }

        if (upper == "POST") {
            res = cli.Post(path.c_str(), raw_body, "application/octet-stream");
        } else if (upper == "PUT") {
            res = cli.Put(path.c_str(), raw_body, "application/octet-stream");
        } else if (upper == "DELETE") {
            res = cli.Delete(path.c_str());
        } else {
            res = cli.Get(path.c_str());
        }
    } else {
        res = cli.Get(path.c_str());
    }

    if (!res) {
        out_err = "transport_error";
        return false;
    }

    std::smatch m;
    if (!std::regex_search(res->body, m, re)) {
        std::string composite;
        for (const auto& h : res->headers) {
            composite += h.first;
            composite += ": ";
            composite += h.second;
            composite += "\n";
        }
        if (std::regex_search(composite, m, re)) {
        } else {
            out_err = "extraction_miss";
            return false;
        }
    }

    int group = cfg.capture_group;
    if (group < 0) group = 0;
    if (m.size() > 1) {
        if (static_cast<size_t>(group) < m.size()) {
            out_token = m[group].str();
            return true;
        }
        out_token = m[0].str();
        return true;
    }
    out_token = m[0].str();
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
        work_queue::post([coll_ref, cfg_snapshot, re_copy]() {
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
            }
            coll_ref->in_flight.fetch_sub(1);
        });
    }

    while (coll->in_flight.load() > 0) {
        Sleep(20);
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

static analysis_result_t analyze_internal(const std::vector<std::string>& tokens)
{
    analysis_result_t a;
    if (tokens.empty()) {
        a.verdict = "no_samples";
        return a;
    }
    a.samples_count = tokens.size();

    std::unordered_map<size_t, size_t> length_hist;
    for (const auto& t : tokens) length_hist[t.size()]++;
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

    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (a.byte_frequency[i] == 0) continue;
        double p = static_cast<double>(a.byte_frequency[i]) / n;
        entropy -= p * (std::log(p) / std::log(2.0));
    }
    a.shannon_entropy_bits = entropy;

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

    for (size_t i = 0; i < mode_len; ++i) {
        if (i >= 256) break;
        size_t accum = 0;
        size_t count = 0;
        for (const auto& t : tokens) {
            if (i < t.size()) { accum += static_cast<uint8_t>(t[i]); ++count; }
        }
        a.position_bias[i] = count > 0 ? (static_cast<double>(accum) / static_cast<double>(count)) - 127.5 : 0.0;
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
            std::vector<size_t> T(1 << L, 0);
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

    bool fips_ok = false;
    if (total_bits >= 20000) {
        bool monobit_ok = (ones >= 9725 && ones <= 10275);
        bool poker_ok = (a.poker_p_value > 0.0001 && a.poker_p_value < 0.9999);
        bool runs_ok = (a.runs_p_value > 0.0001);
        bool long_run_ok = (a.long_run_p_value > 0.0001);
        fips_ok = monobit_ok && poker_ok && runs_ok && long_run_ok;
    }
    a.passes_fips_140_2 = fips_ok;
    a.valid = true;

    double score = 0.0;
    int counted = 0;
    if (!std::isnan(a.monobit_p_value))   { score += a.monobit_p_value;   ++counted; }
    if (!std::isnan(a.poker_p_value))     { score += a.poker_p_value;     ++counted; }
    if (!std::isnan(a.runs_p_value))      { score += a.runs_p_value;      ++counted; }
    if (!std::isnan(a.long_run_p_value))  { score += a.long_run_p_value;  ++counted; }
    if (!std::isnan(a.chi_square_p_value)){ score += a.chi_square_p_value;++counted; }
    double avg = counted > 0 ? score / counted : 0.0;

    if (a.samples_count < 50) {
        a.verdict = "Inconclusive (sample too small, collect >=200 for FIPS verdict)";
    } else if (a.samples_count < 200) {
        a.verdict = avg > 0.05 ? "Adequate (limited sample)" : "Poor (limited sample)";
    } else if (avg > 0.20 && fips_ok)     a.verdict = "Excellent";
    else if (avg > 0.05 && fips_ok)       a.verdict = "Good";
    else if (avg > 0.01)                  a.verdict = "Adequate";
    else                                  a.verdict = "Poor";

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
        g_reg.collections[coll->id] = coll;
    }

    std::shared_ptr<collection_t> coll_ref = coll;
    work_queue::post([coll_ref]() {
        collection_worker(coll_ref);
    });

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
    collection_status_t s;
    std::shared_ptr<collection_t> coll;
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        auto it = g_reg.collections.find(id);
        if (it == g_reg.collections.end()) return s;
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
    return s;
}

std::vector<std::string> samples(uint64_t id, size_t max_count)
{
    std::shared_ptr<collection_t> coll;
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        auto it = g_reg.collections.find(id);
        if (it == g_reg.collections.end()) return {};
        coll = it->second;
    }
    std::lock_guard<std::mutex> lk(coll->samples_mtx);
    if (max_count == 0 || max_count >= coll->samples.size()) return coll->samples;
    return std::vector<std::string>(coll->samples.end() - static_cast<ptrdiff_t>(max_count), coll->samples.end());
}

analysis_result_t analyze(uint64_t id)
{
    std::shared_ptr<collection_t> coll;
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        auto it = g_reg.collections.find(id);
        if (it == g_reg.collections.end()) {
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
    analysis_result_t r = analyze_internal(snap);
    r.collection_id = id;
    return r;
}

std::vector<collection_status_t> list_collections()
{
    std::vector<collection_status_t> out;
    std::vector<uint64_t> ids;
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        ids.reserve(g_reg.collections.size());
        for (const auto& kv : g_reg.collections) ids.push_back(kv.first);
    }
    out.reserve(ids.size());
    for (uint64_t id : ids) out.push_back(status(id));
    return out;
}

bool delete_collection(uint64_t id)
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
    while (coll->in_flight.load() > 0) Sleep(5);
    {
        std::lock_guard<std::mutex> lk(g_reg.mtx);
        g_reg.collections.erase(id);
    }
    return true;
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(g_reg.err_mtx);
    return g_reg.last_err;
}

}
}
}
