#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../network/protocol_parser.hpp"
#include "../network/http_parser_engine.hpp"
#include "../network/http2_session.hpp"
#include "../../helpers/diag_log.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

void proof_log(const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    diag::log_tagged("parser_proof", buf);
    std::printf("[parser_proof] %s\n", buf);
}

void log_request_case(const char* name, const protocol_parser::http_request& req)
{
    proof_log("CASE %s request valid=%d complete=%d consumed=%zu method=%s uri_len=%zu headers=%zu body=%zu",
        name,
        req.valid ? 1 : 0,
        req.complete ? 1 : 0,
        req.total_consumed,
        req.method.empty() ? "(empty)" : req.method.c_str(),
        req.uri.size(),
        req.headers.size(),
        req.body.size());
}

void log_response_case(const char* name, const protocol_parser::http_response& resp)
{
    proof_log("CASE %s response valid=%d complete=%d consumed=%zu status=%d headers=%zu body=%zu",
        name,
        resp.valid ? 1 : 0,
        resp.complete ? 1 : 0,
        resp.total_consumed,
        resp.status_code,
        resp.headers.size(),
        resp.body.size());
}

void record_result(const char* name, bool ok, int& passed, int& failed)
{
    proof_log("ASSERT %s result=%s", name, ok ? "PASS" : "FAIL");
    if (ok) {
        ++passed;
    } else {
        ++failed;
    }
}

bool run_http1_suite(int& passed, int& failed)
{
    proof_log("HTTP/1 parser edge suite START source=AiDAParserProof");

    const char dup_bad[] = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nbody!";
    auto dup_bad_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(dup_bad), sizeof(dup_bad) - 1);
    log_request_case("duplicate_content_length_mismatch", dup_bad_req);
    record_result("duplicate_content_length_mismatch_rejected", !dup_bad_req.valid, passed, failed);

    const char dup_good[] = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nbodyextra";
    auto dup_good_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(dup_good), sizeof(dup_good) - 1);
    log_request_case("duplicate_content_length_match", dup_good_req);
    record_result("duplicate_content_length_match_consumes_declared_body",
        dup_good_req.valid && dup_good_req.complete && dup_good_req.body.size() == 4 &&
        dup_good_req.total_consumed == (sizeof(dup_good) - 1) - 5,
        passed, failed);

    const char cl_te[] = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    auto cl_te_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(cl_te), sizeof(cl_te) - 1);
    auto cl_te_llhttp = http_engine::parse_request(reinterpret_cast<const uint8_t*>(cl_te), sizeof(cl_te) - 1);
    log_request_case("content_length_transfer_encoding_manual", cl_te_req);
    log_request_case("content_length_transfer_encoding_llhttp", cl_te_llhttp);
    record_result("content_length_transfer_encoding_rejected_by_both", !cl_te_req.valid && !cl_te_llhttp.valid, passed, failed);

    const char bad_chunk[] = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5x\r\nhello\r\n0\r\n\r\n";
    auto bad_chunk_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(bad_chunk), sizeof(bad_chunk) - 1);
    log_request_case("invalid_chunk_size", bad_chunk_req);
    record_result("invalid_chunk_size_rejected", !bad_chunk_req.valid, passed, failed);

    const char partial_chunk[] = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
    auto partial_chunk_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(partial_chunk), sizeof(partial_chunk) - 1);
    log_request_case("partial_chunk_data", partial_chunk_req);
    record_result("partial_chunk_data_incomplete_not_invalid",
        partial_chunk_req.valid && !partial_chunk_req.complete,
        passed, failed);

    const char chunk_trailer[] = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: ok\r\n\r\nEXTRA";
    auto trailer_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(chunk_trailer), sizeof(chunk_trailer) - 1);
    log_request_case("chunked_with_trailer_and_extra", trailer_req);
    record_result("chunked_with_trailer_consumes_exact_message",
        trailer_req.valid && trailer_req.complete &&
        std::string(trailer_req.body.begin(), trailer_req.body.end()) == "Wikipedia" &&
        trailer_req.total_consumed == (sizeof(chunk_trailer) - 1) - 5,
        passed, failed);

    const char folded[] = "GET / HTTP/1.1\r\nHost: a\r\nX-Test: one\r\n\t two\r\n\r\n";
    auto folded_req = protocol_parser::parse_http_request(reinterpret_cast<const uint8_t*>(folded), sizeof(folded) - 1);
    log_request_case("obs_fold_unfold", folded_req);
    std::string folded_value = protocol_parser::find_header(folded_req.headers, "X-Test");
    proof_log("CASE obs_fold_unfold header_value_len=%zu", folded_value.size());
    record_result("obs_fold_unfolds_to_single_space", folded_req.valid && folded_value == "one two", passed, failed);

    const char no_body_resp_raw[] = "HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\nignored";
    auto no_body_resp = protocol_parser::parse_http_response(reinterpret_cast<const uint8_t*>(no_body_resp_raw), sizeof(no_body_resp_raw) - 1);
    log_response_case("response_204_no_body", no_body_resp);
    record_result("response_204_ignores_declared_body",
        no_body_resp.valid && no_body_resp.complete && no_body_resp.body.empty(),
        passed, failed);

    const bool ok = !dup_bad_req.valid &&
        dup_good_req.valid && dup_good_req.complete && dup_good_req.body.size() == 4 &&
        dup_good_req.total_consumed == (sizeof(dup_good) - 1) - 5 &&
        !cl_te_req.valid && !cl_te_llhttp.valid &&
        !bad_chunk_req.valid &&
        partial_chunk_req.valid && !partial_chunk_req.complete &&
        trailer_req.valid && trailer_req.complete &&
        std::string(trailer_req.body.begin(), trailer_req.body.end()) == "Wikipedia" &&
        trailer_req.total_consumed == (sizeof(chunk_trailer) - 1) - 5 &&
        folded_req.valid && folded_value == "one two" &&
        no_body_resp.valid && no_body_resp.complete && no_body_resp.body.empty();

    proof_log("HTTP/1 parser edge suite %s", ok ? "PASS" : "FAIL");
    return ok;
}

bool run_http2_suite(int& passed, int& failed)
{
    proof_log("HTTP/2 client preface/settings suite START source=AiDAParserProof");
    std::vector<uint8_t> sent;
    h2_session::session s(h2_session::session::role::client);
    bool init_ok = s.initialize([&](const uint8_t* data, size_t len) -> ssize_t {
        sent.insert(sent.end(), data, data + len);
        return static_cast<ssize_t>(len);
    });

    const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    bool has_preface = sent.size() >= 33 && std::memcmp(sent.data(), preface, sizeof(preface) - 1) == 0;
    bool has_settings = has_preface && sent[27] == 0x04 && sent[28] == 0x00 &&
        sent[29] == 0x00 && sent[30] == 0x00 && sent[31] == 0x00 && sent[32] == 0x00;
    proof_log("CASE h2_client_preface_settings init=%d bytes=%zu preface=%d first_frame_type=%u first_frame_flags=0x%02X first_frame_stream=%u",
        init_ok ? 1 : 0,
        sent.size(),
        has_preface ? 1 : 0,
        sent.size() > 27 ? static_cast<unsigned>(sent[27]) : 0u,
        sent.size() > 28 ? static_cast<unsigned>(sent[28]) : 0u,
        sent.size() > 32 ? ((static_cast<unsigned>(sent[29]) << 24) | (static_cast<unsigned>(sent[30]) << 16) | (static_cast<unsigned>(sent[31]) << 8) | static_cast<unsigned>(sent[32])) : 0u);
    record_result("h2_client_preface_settings_emitted", init_ok && has_settings, passed, failed);

    bool ok = init_ok && has_settings;
    proof_log("HTTP/2 client preface/settings suite %s", ok ? "PASS" : "FAIL");
    return ok;
}

}

int main()
{
    int passed = 0;
    int failed = 0;
    proof_log("AiDAParserProof executable START");
    bool h1 = run_http1_suite(passed, failed);
    bool h2 = run_http2_suite(passed, failed);
    proof_log("AiDAParserProof executable DONE passed=%d failed=%d h1=%d h2=%d", passed, failed, h1 ? 1 : 0, h2 ? 1 : 0);
    return failed == 0 ? 0 : 1;
}
