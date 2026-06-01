#pragma once

#include "protocol_parser.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

namespace http_engine {

inline protocol_parser::http_request parse_request(const uint8_t* data, size_t len) {
    if (!data || len == 0) return {};
    auto req = protocol_parser::parse_http_request(data, len);
    diag::log_tagged_fmt("http_parser", "parse_request manual len=%zu valid=%d complete=%d consumed=%zu",
        len,
        req.valid ? 1 : 0,
        req.complete ? 1 : 0,
        req.total_consumed);
    return req;
}

inline protocol_parser::http_response parse_response(const uint8_t* data, size_t len) {
    if (!data || len == 0) return {};
    auto resp = protocol_parser::parse_http_response(data, len);
    diag::log_tagged_fmt("http_parser", "parse_response manual len=%zu valid=%d complete=%d consumed=%zu",
        len,
        resp.valid ? 1 : 0,
        resp.complete ? 1 : 0,
        resp.total_consumed);
    return resp;
}

class stream_parser {
public:
    enum class mode { request, response };

    explicit stream_parser(mode m) : mode_(m) {}

    bool feed(const uint8_t* data, size_t len) {
        if (complete_) return true;
        if (!data && len != 0) {
            parse_error_ = true;
            return false;
        }
        if (len != 0) {
            if (buffer_.size() > max_buffer_size_ || len > max_buffer_size_ - buffer_.size()) {
                parse_error_ = true;
                diag::log_tagged_fmt("http_parser", "stream_feed buffer_limit side=%s buffered=%zu incoming=%zu",
                    mode_ == mode::request ? "request" : "response",
                    buffer_.size(),
                    len);
                return false;
            }
            buffer_.insert(buffer_.end(), data, data + len);
        }

        if (mode_ == mode::request) {
            request_ = protocol_parser::parse_http_request(buffer_.data(), buffer_.size());
            complete_ = request_.complete;
            if (!request_.valid && buffer_.size() >= max_incomplete_header_size_)
                parse_error_ = true;
        } else {
            response_ = protocol_parser::parse_http_response(buffer_.data(), buffer_.size());
            complete_ = response_.complete;
            if (!response_.valid && buffer_.size() >= max_incomplete_header_size_)
                parse_error_ = true;
        }

        diag::log_tagged_fmt("http_parser", "stream_feed manual side=%s buffered=%zu complete=%d error=%d",
            mode_ == mode::request ? "request" : "response",
            buffer_.size(),
            complete_ ? 1 : 0,
            parse_error_ ? 1 : 0);
        return complete_;
    }

    bool complete() const { return complete_; }
    bool error() const { return parse_error_; }

    protocol_parser::http_request get_request() const { return request_; }
    protocol_parser::http_response get_response() const { return response_; }

    void reset() {
        buffer_.clear();
        request_ = {};
        response_ = {};
        complete_ = false;
        parse_error_ = false;
    }

private:
    static constexpr size_t max_buffer_size_ = 16u * 1024u * 1024u;
    static constexpr size_t max_incomplete_header_size_ = 128u * 1024u;

    mode mode_;
    std::vector<uint8_t> buffer_;
    protocol_parser::http_request request_;
    protocol_parser::http_response response_;
    bool complete_ = false;
    bool parse_error_ = false;
};

}
