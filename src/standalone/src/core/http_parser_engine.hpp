#pragma once


#include "protocol_parser.hpp"

#include <llhttp.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace http_engine {


struct parse_ctx {

    protocol_parser::http_request  req;
    protocol_parser::http_response resp;
    bool is_request = true;


    std::string cur_header_field;
    std::string cur_header_value;
    bool        header_field_active = false;


    std::vector<uint8_t> body;


    bool message_complete = false;
    size_t bytes_consumed = 0;
};


namespace detail {

inline int on_url(llhttp_t* p, const char* at, size_t len) {
    auto* ctx = static_cast<parse_ctx*>(p->data);
    ctx->req.uri.append(at, len);
    return 0;
}

inline int on_status(llhttp_t* p, const char* at, size_t len) {
    auto* ctx = static_cast<parse_ctx*>(p->data);
    ctx->resp.reason.append(at, len);
    return 0;
}

inline int on_header_field(llhttp_t* p, const char* at, size_t len) {
    auto* ctx = static_cast<parse_ctx*>(p->data);

    if (ctx->header_field_active && !ctx->cur_header_value.empty()) {
        protocol_parser::http_header hdr;
        hdr.name  = std::move(ctx->cur_header_field);
        hdr.value = std::move(ctx->cur_header_value);
        if (ctx->is_request)
            ctx->req.headers.push_back(std::move(hdr));
        else
            ctx->resp.headers.push_back(std::move(hdr));
        ctx->cur_header_field.clear();
        ctx->cur_header_value.clear();
    }
    ctx->cur_header_field.append(at, len);
    ctx->header_field_active = true;
    return 0;
}

inline int on_header_value(llhttp_t* p, const char* at, size_t len) {
    auto* ctx = static_cast<parse_ctx*>(p->data);
    ctx->cur_header_value.append(at, len);
    ctx->header_field_active = false;
    return 0;
}

inline int on_headers_complete(llhttp_t* p) {
    auto* ctx = static_cast<parse_ctx*>(p->data);

    if (!ctx->cur_header_field.empty()) {
        protocol_parser::http_header hdr;
        hdr.name  = std::move(ctx->cur_header_field);
        hdr.value = std::move(ctx->cur_header_value);
        if (ctx->is_request)
            ctx->req.headers.push_back(std::move(hdr));
        else
            ctx->resp.headers.push_back(std::move(hdr));
        ctx->cur_header_field.clear();
        ctx->cur_header_value.clear();
    }

    if (ctx->is_request) {
        ctx->req.method  = llhttp_method_name(static_cast<llhttp_method_t>(p->method));
        ctx->req.version = "HTTP/" + std::to_string(p->http_major) + "." + std::to_string(p->http_minor);
        ctx->req.valid   = true;
    } else {
        ctx->resp.status_code = static_cast<int>(p->status_code);
        ctx->resp.version     = "HTTP/" + std::to_string(p->http_major) + "." + std::to_string(p->http_minor);
        ctx->resp.valid       = true;
    }
    return 0;
}

inline int on_body(llhttp_t* p, const char* at, size_t len) {
    auto* ctx = static_cast<parse_ctx*>(p->data);
    ctx->body.insert(ctx->body.end(),
                     reinterpret_cast<const uint8_t*>(at),
                     reinterpret_cast<const uint8_t*>(at) + len);
    return 0;
}

inline int on_message_complete(llhttp_t* p) {
    auto* ctx = static_cast<parse_ctx*>(p->data);
    if (ctx->is_request) {
        ctx->req.body     = ctx->body;
        ctx->req.complete = true;
    } else {
        ctx->resp.body     = ctx->body;
        ctx->resp.complete = true;
    }
    ctx->message_complete = true;
    return HPE_PAUSED;
}

}


inline llhttp_settings_t make_settings() {
    llhttp_settings_t s;
    llhttp_settings_init(&s);
    s.on_url              = detail::on_url;
    s.on_status           = detail::on_status;
    s.on_header_field     = detail::on_header_field;
    s.on_header_value     = detail::on_header_value;
    s.on_headers_complete = detail::on_headers_complete;
    s.on_body             = detail::on_body;
    s.on_message_complete = detail::on_message_complete;
    return s;
}


inline protocol_parser::http_request parse_request(const uint8_t* data, size_t len) {
    if (!data || len == 0) return {};

    static thread_local llhttp_settings_t settings = make_settings();

    parse_ctx ctx;
    ctx.is_request = true;

    llhttp_t parser;
    llhttp_init(&parser, HTTP_REQUEST, &settings);
    parser.data = &ctx;

    llhttp_errno_t err = llhttp_execute(&parser, reinterpret_cast<const char*>(data), len);

    if (ctx.message_complete || ctx.req.valid) {


        const char* error_pos = llhttp_get_error_pos(&parser);
        if (error_pos && err == HPE_PAUSED) {
            ctx.req.total_consumed = static_cast<size_t>(
                error_pos - reinterpret_cast<const char*>(data));
        } else {
            ctx.req.total_consumed = len;
        }
        return ctx.req;
    }


    return protocol_parser::parse_http_request(data, len);
}


inline protocol_parser::http_response parse_response(const uint8_t* data, size_t len) {
    if (!data || len == 0) return {};

    static thread_local llhttp_settings_t settings = make_settings();

    parse_ctx ctx;
    ctx.is_request = false;

    llhttp_t parser;
    llhttp_init(&parser, HTTP_RESPONSE, &settings);
    parser.data = &ctx;

    llhttp_errno_t err = llhttp_execute(&parser, reinterpret_cast<const char*>(data), len);

    if (ctx.message_complete || ctx.resp.valid) {
        const char* error_pos = llhttp_get_error_pos(&parser);
        if (error_pos && err == HPE_PAUSED) {
            ctx.resp.total_consumed = static_cast<size_t>(
                error_pos - reinterpret_cast<const char*>(data));
        } else {
            ctx.resp.total_consumed = len;
        }
        return ctx.resp;
    }

    return protocol_parser::parse_http_response(data, len);
}


class stream_parser {
public:
    enum class mode { request, response };

    explicit stream_parser(mode m) : mode_(m) {
        llhttp_settings_init(&settings_);
        settings_.on_url              = detail::on_url;
        settings_.on_status           = detail::on_status;
        settings_.on_header_field     = detail::on_header_field;
        settings_.on_header_value     = detail::on_header_value;
        settings_.on_headers_complete = detail::on_headers_complete;
        settings_.on_body             = detail::on_body;
        settings_.on_message_complete = detail::on_message_complete;

        llhttp_init(&parser_, (m == mode::request) ? HTTP_REQUEST : HTTP_RESPONSE, &settings_);
        ctx_.is_request = (m == mode::request);
        parser_.data = &ctx_;
    }


    bool feed(const uint8_t* data, size_t len) {
        if (ctx_.message_complete) return true;
        llhttp_errno_t err = llhttp_execute(&parser_,
            reinterpret_cast<const char*>(data), len);
        if (err == HPE_PAUSED) {

            llhttp_resume(&parser_);
        }
        return ctx_.message_complete;
    }

    bool complete() const { return ctx_.message_complete; }

    protocol_parser::http_request  get_request()  const { return ctx_.req; }
    protocol_parser::http_response get_response() const { return ctx_.resp; }


    void reset() {
        ctx_ = {};
        ctx_.is_request = (mode_ == mode::request);
        llhttp_init(&parser_, (mode_ == mode::request) ? HTTP_REQUEST : HTTP_RESPONSE, &settings_);
        parser_.data = &ctx_;
    }

private:
    mode              mode_;
    llhttp_t          parser_{};
    llhttp_settings_t settings_{};
    parse_ctx         ctx_;
};

}
