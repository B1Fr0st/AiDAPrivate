#pragma once


#include "protocol_parser.hpp"
#include "helpers/diag_log.hpp"

#include <llhttp.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
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
    bool parse_error = false;
    size_t bytes_consumed = 0;
};


namespace detail {

inline void commit_header(parse_ctx* ctx) {
    if (!ctx || ctx->cur_header_field.empty()) return;
    size_t count_before = ctx->is_request ? ctx->req.headers.size() : ctx->resp.headers.size();
    diag::log_tagged_fmt("http_parser", "llhttp_commit_header side=%s index=%zu name=%s value_len=%zu",
        ctx->is_request ? "request" : "response",
        count_before,
        ctx->cur_header_field.c_str(),
        ctx->cur_header_value.size());
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

    if (!ctx->header_field_active)
        commit_header(ctx);
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

    commit_header(ctx);

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
    diag::log_tagged_fmt("http_parser", "parse_request llhttp_execute len=%zu err=%d err_name=%s valid=%d complete=%d headers=%zu body=%zu",
        len,
        static_cast<int>(err),
        llhttp_errno_name(err),
        static_cast<int>(ctx.req.valid),
        static_cast<int>(ctx.message_complete),
        ctx.req.headers.size(),
        ctx.body.size());
    if (err != HPE_OK && err != HPE_PAUSED && err != HPE_PAUSED_UPGRADE) {
        diag::log_tagged_fmt("http_parser", "parse_request strict_reject err=%d err_name=%s", static_cast<int>(err), llhttp_errno_name(err));
        return {};
    }

    if (ctx.message_complete || ctx.req.valid) {
        const char* error_pos = llhttp_get_error_pos(&parser);
        if (err == HPE_PAUSED_UPGRADE)
            ctx.req.complete = true;
        if (error_pos && (err == HPE_PAUSED || err == HPE_PAUSED_UPGRADE)) {
            ctx.req.total_consumed = static_cast<size_t>(
                error_pos - reinterpret_cast<const char*>(data));
        } else {
            ctx.req.total_consumed = len;
        }
        diag::log_tagged_fmt("http_parser", "parse_request result valid=%d complete=%d consumed=%zu method=%s uri_len=%zu headers=%zu body=%zu",
            static_cast<int>(ctx.req.valid),
            static_cast<int>(ctx.req.complete),
            ctx.req.total_consumed,
            ctx.req.method.c_str(),
            ctx.req.uri.size(),
            ctx.req.headers.size(),
            ctx.req.body.size());
        return ctx.req;
    }


    diag::log_tagged_fmt("http_parser", "parse_request fallback_manual len=%zu", len);
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
    diag::log_tagged_fmt("http_parser", "parse_response llhttp_execute len=%zu err=%d err_name=%s valid=%d complete=%d headers=%zu body=%zu",
        len,
        static_cast<int>(err),
        llhttp_errno_name(err),
        static_cast<int>(ctx.resp.valid),
        static_cast<int>(ctx.message_complete),
        ctx.resp.headers.size(),
        ctx.body.size());
    if (err != HPE_OK && err != HPE_PAUSED && err != HPE_PAUSED_UPGRADE) {
        diag::log_tagged_fmt("http_parser", "parse_response strict_reject err=%d err_name=%s", static_cast<int>(err), llhttp_errno_name(err));
        return {};
    }

    if (ctx.message_complete || ctx.resp.valid) {
        const char* error_pos = llhttp_get_error_pos(&parser);
        if (err == HPE_PAUSED_UPGRADE)
            ctx.resp.complete = true;
        if (error_pos && (err == HPE_PAUSED || err == HPE_PAUSED_UPGRADE)) {
            ctx.resp.total_consumed = static_cast<size_t>(
                error_pos - reinterpret_cast<const char*>(data));
        } else {
            ctx.resp.total_consumed = len;
        }
        diag::log_tagged_fmt("http_parser", "parse_response result valid=%d complete=%d consumed=%zu status=%d headers=%zu body=%zu",
            static_cast<int>(ctx.resp.valid),
            static_cast<int>(ctx.resp.complete),
            ctx.resp.total_consumed,
            ctx.resp.status_code,
            ctx.resp.headers.size(),
            ctx.resp.body.size());
        return ctx.resp;
    }

    diag::log_tagged_fmt("http_parser", "parse_response fallback_manual len=%zu", len);
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
        diag::log_tagged_fmt("http_parser", "stream_feed side=%s len=%zu err=%d err_name=%s complete=%d headers_req=%zu headers_resp=%zu body=%zu",
            ctx_.is_request ? "request" : "response",
            len,
            static_cast<int>(err),
            llhttp_errno_name(err),
            static_cast<int>(ctx_.message_complete),
            ctx_.req.headers.size(),
            ctx_.resp.headers.size(),
            ctx_.body.size());
        if (err == HPE_PAUSED) {

            llhttp_resume(&parser_);
        } else if (err == HPE_PAUSED_UPGRADE) {
            if (ctx_.is_request)
                ctx_.req.complete = true;
            else
                ctx_.resp.complete = true;
            ctx_.message_complete = true;
        } else if (err != HPE_OK) {
            ctx_.parse_error = true;
            diag::log_tagged_fmt("http_parser", "stream_feed strict_error side=%s err=%d err_name=%s",
                ctx_.is_request ? "request" : "response",
                static_cast<int>(err),
                llhttp_errno_name(err));
        }
        return ctx_.message_complete;
    }

    bool complete() const { return ctx_.message_complete; }
    bool error() const { return ctx_.parse_error; }

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
