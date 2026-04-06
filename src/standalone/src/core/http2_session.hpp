#pragma once


#include "protocol_parser.hpp"

#ifdef _WIN32
#  include <BaseTsd.h>
   typedef SSIZE_T ssize_t;
#endif

#include <nghttp2/nghttp2.h>

#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace h2_session {


struct stream_data {
    int32_t  stream_id = 0;


    std::string method;
    std::string path;
    std::string authority;
    std::string scheme;
    std::vector<protocol_parser::http_header> request_headers;
    std::vector<uint8_t> request_body;
    bool request_complete = false;


    int         status_code = 0;
    std::vector<protocol_parser::http_header> response_headers;
    std::vector<uint8_t> response_body;
    bool response_complete = false;


    bool is_grpc = false;
};


using send_callback_t = std::function<ssize_t(const uint8_t* data, size_t len)>;


using on_request_t = std::function<void(const stream_data& stream)>;


using on_response_t = std::function<void(const stream_data& stream)>;


class session {
public:
    enum class role { client, server };

    explicit session(role r) : role_(r) {}

    ~session() {
        if (session_) nghttp2_session_del(session_);
    }

    session(const session&) = delete;
    session& operator=(const session&) = delete;

    session(session&& other) noexcept
        : role_(other.role_)
        , session_(other.session_)
        , streams_(std::move(other.streams_))
        , send_cb_(std::move(other.send_cb_))
        , on_request_(std::move(other.on_request_))
        , on_response_(std::move(other.on_response_))
    {
        other.session_ = nullptr;
        if (session_) nghttp2_session_set_user_data(session_, this);
    }

    session& operator=(session&& other) noexcept {
        if (this != &other) {
            if (session_) nghttp2_session_del(session_);
            role_       = other.role_;
            session_    = other.session_;
            streams_    = std::move(other.streams_);
            send_cb_    = std::move(other.send_cb_);
            on_request_ = std::move(other.on_request_);
            on_response_= std::move(other.on_response_);
            other.session_ = nullptr;
            if (session_) nghttp2_session_set_user_data(session_, this);
        }
        return *this;
    }


    bool initialize(send_callback_t send_cb) {
        send_cb_ = std::move(send_cb);

        nghttp2_session_callbacks* callbacks = nullptr;
        nghttp2_session_callbacks_new(&callbacks);

        nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header);
        nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers);

        int rv;
        if (role_ == role::server) {
            rv = nghttp2_session_server_new(&session_, callbacks, this);
        } else {
            rv = nghttp2_session_client_new(&session_, callbacks, this);
        }
        nghttp2_session_callbacks_del(callbacks);

        if (rv != 0) return false;


        if (role_ == role::server) {
            nghttp2_settings_entry iv[] = {
                { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
                { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535 }
            };
            rv = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, iv, 2);
            if (rv != 0) return false;
        }

        return flush_send() >= 0;
    }

    void set_on_request(on_request_t cb)  { on_request_  = std::move(cb); }
    void set_on_response(on_response_t cb) { on_response_ = std::move(cb); }


    ssize_t feed(const uint8_t* data, size_t len) {
        ssize_t rv = nghttp2_session_mem_recv(session_, data, len);
        if (rv < 0) return -1;
        if (flush_send() < 0) return -1;
        return rv;
    }


    int32_t submit_request(const std::string& method,
                           const std::string& path,
                           const std::string& authority,
                           const std::string& scheme,
                           const std::vector<protocol_parser::http_header>& headers,
                           const std::vector<uint8_t>& body) {

        std::vector<nghttp2_nv> nva;
        nva.reserve(headers.size() + 4);

        auto push_nv = [&](const std::string& n, const std::string& v) {
            nghttp2_nv nv;
            nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(n.data()));
            nv.namelen = n.size();
            nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(v.data()));
            nv.valuelen = v.size();
            nv.flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
            nva.push_back(nv);
        };

        push_nv(":method", method);
        push_nv(":path", path);
        push_nv(":scheme", scheme);
        push_nv(":authority", authority);

        for (auto& h : headers) push_nv(h.name, h.value);

        nghttp2_data_provider prd;
        body_source src;
        src.data = body.data();
        src.len  = body.size();
        src.pos  = 0;
        prd.source.ptr = &src;
        prd.read_callback = body_read_callback;

        int32_t stream_id = nghttp2_submit_request(session_, nullptr,
            nva.data(), nva.size(),
            body.empty() ? nullptr : &prd, nullptr);

        if (stream_id < 0) return -1;

        auto& sd = streams_[stream_id];
        sd.stream_id  = stream_id;
        sd.method     = method;
        sd.path       = path;
        sd.authority  = authority;
        sd.scheme     = scheme;
        sd.request_headers = headers;
        sd.request_body    = body;
        sd.request_complete = true;


        for (auto& h : headers) {
            if (h.name == "content-type" && h.value.find("application/grpc") != std::string::npos) {
                sd.is_grpc = true;
                break;
            }
        }

        flush_send();
        return stream_id;
    }


    bool submit_response(int32_t stream_id, int status_code,
                         const std::vector<protocol_parser::http_header>& headers,
                         const std::vector<uint8_t>& body) {

        std::vector<nghttp2_nv> nva;
        nva.reserve(headers.size() + 1);

        std::string status_str = std::to_string(status_code);
        nghttp2_nv status_nv;
        status_nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(":status"));
        status_nv.namelen  = 7;
        status_nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(status_str.data()));
        status_nv.valuelen = status_str.size();
        status_nv.flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
        nva.push_back(status_nv);

        for (auto& h : headers) {
            nghttp2_nv nv;
            nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(h.name.data()));
            nv.namelen = h.name.size();
            nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(h.value.data()));
            nv.valuelen = h.value.size();
            nv.flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
            nva.push_back(nv);
        }

        nghttp2_data_provider prd;
        body_source src;
        src.data = body.data();
        src.len  = body.size();
        src.pos  = 0;
        prd.source.ptr = &src;
        prd.read_callback = body_read_callback;

        int rv = nghttp2_submit_response(session_, stream_id,
            nva.data(), nva.size(),
            body.empty() ? nullptr : &prd);

        if (rv != 0) return false;
        return flush_send() >= 0;
    }


    bool want_read()  const { return nghttp2_session_want_read(session_) != 0; }
    bool want_write() const { return nghttp2_session_want_write(session_) != 0; }

    const stream_data* find_stream(int32_t stream_id) const {
        auto it = streams_.find(stream_id);
        return (it != streams_.end()) ? &it->second : nullptr;
    }

    std::vector<stream_data> get_all_streams() const {
        std::vector<stream_data> result;
        result.reserve(streams_.size());
        for (auto& [id, sd] : streams_) result.push_back(sd);
        return result;
    }

private:
    role                          role_;
    nghttp2_session*              session_ = nullptr;
    std::map<int32_t, stream_data> streams_;
    send_callback_t               send_cb_;
    on_request_t                  on_request_;
    on_response_t                 on_response_;


    struct body_source {
        const uint8_t* data = nullptr;
        size_t len = 0;
        size_t pos = 0;
    };

    static ssize_t body_read_callback(nghttp2_session* , int32_t ,
                                      uint8_t* buf, size_t length,
                                      uint32_t* data_flags,
                                      nghttp2_data_source* source,
                                      void* ) {
        auto* src = static_cast<body_source*>(source->ptr);
        size_t remaining = src->len - src->pos;
        size_t to_copy = (std::min)(remaining, length);
        if (to_copy > 0) {
            memcpy(buf, src->data + src->pos, to_copy);
            src->pos += to_copy;
        }
        if (src->pos >= src->len) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        return static_cast<ssize_t>(to_copy);
    }


    ssize_t flush_send() {
        while (nghttp2_session_want_write(session_)) {
            const uint8_t* data = nullptr;
            ssize_t len = nghttp2_session_mem_send(session_, &data);
            if (len < 0) return -1;
            if (len == 0) break;
            if (send_cb_) {
                ssize_t written = send_cb_(data, static_cast<size_t>(len));
                if (written < 0) return -1;
            }
        }
        return 0;
    }


    static ssize_t send_callback(nghttp2_session* ,
                                 const uint8_t* data, size_t length,
                                 int , void* user_data) {
        auto* self = static_cast<session*>(user_data);
        if (self->send_cb_) return self->send_cb_(data, length);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    static int on_begin_headers(nghttp2_session* ,
                                const nghttp2_frame* frame, void* user_data) {
        auto* self = static_cast<session*>(user_data);
        if (frame->hd.type == NGHTTP2_HEADERS) {
            auto& sd = self->streams_[frame->hd.stream_id];
            sd.stream_id = frame->hd.stream_id;
        }
        return 0;
    }

    static int on_header(nghttp2_session* , const nghttp2_frame* frame,
                         const uint8_t* name, size_t namelen,
                         const uint8_t* value, size_t valuelen,
                         uint8_t , void* user_data) {
        auto* self = static_cast<session*>(user_data);
        auto it = self->streams_.find(frame->hd.stream_id);
        if (it == self->streams_.end()) return 0;
        auto& sd = it->second;

        std::string n(reinterpret_cast<const char*>(name), namelen);
        std::string v(reinterpret_cast<const char*>(value), valuelen);


        if (n == ":method")    { sd.method    = v; return 0; }
        if (n == ":path")      { sd.path      = v; return 0; }
        if (n == ":authority") { sd.authority  = v; return 0; }
        if (n == ":scheme")    { sd.scheme     = v; return 0; }
        if (n == ":status")    {
            sd.status_code = std::stoi(v);
            return 0;
        }


        protocol_parser::http_header hdr;
        hdr.name  = std::move(n);
        hdr.value = std::move(v);


        if (frame->headers.cat == NGHTTP2_HCAT_REQUEST ||
            frame->headers.cat == NGHTTP2_HCAT_PUSH_RESPONSE) {
            sd.request_headers.push_back(std::move(hdr));

            if (sd.request_headers.back().name == "content-type" &&
                sd.request_headers.back().value.find("application/grpc") != std::string::npos) {
                sd.is_grpc = true;
            }
        } else {
            sd.response_headers.push_back(std::move(hdr));
        }
        return 0;
    }

    static int on_data_chunk_recv(nghttp2_session* , uint8_t ,
                                  int32_t stream_id, const uint8_t* data,
                                  size_t len, void* user_data) {
        auto* self = static_cast<session*>(user_data);
        auto it = self->streams_.find(stream_id);
        if (it == self->streams_.end()) return 0;
        auto& sd = it->second;


        if (!sd.request_complete && self->role_ == role::server) {
            sd.request_body.insert(sd.request_body.end(), data, data + len);
        } else {
            sd.response_body.insert(sd.response_body.end(), data, data + len);
        }
        return 0;
    }

    static int on_frame_recv(nghttp2_session* ,
                             const nghttp2_frame* frame, void* user_data) {
        auto* self = static_cast<session*>(user_data);

        if (frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) {
            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                auto it = self->streams_.find(frame->hd.stream_id);
                if (it != self->streams_.end()) {
                    auto& sd = it->second;
                    if (self->role_ == role::server && !sd.request_complete) {
                        sd.request_complete = true;
                        if (self->on_request_) self->on_request_(sd);
                    } else {
                        sd.response_complete = true;
                        if (self->on_response_) self->on_response_(sd);
                    }
                }
            }
        }
        return 0;
    }

    static int on_stream_close(nghttp2_session* , int32_t stream_id,
                               uint32_t , void* user_data) {
        auto* self = static_cast<session*>(user_data);

        (void)self;
        (void)stream_id;
        return 0;
    }
};

}
