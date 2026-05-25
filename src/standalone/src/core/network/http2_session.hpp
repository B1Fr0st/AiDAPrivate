#pragma once


#include "protocol_parser.hpp"
#include "helpers/diag_log.hpp"

#ifdef _WIN32
#  include <BaseTsd.h>
   typedef SSIZE_T ssize_t;
#endif

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
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

    struct grpc_message {
        bool compressed = false;
        uint32_t length = 0;
        std::vector<uint8_t> payload;
    };
    std::vector<grpc_message> request_grpc_messages;
    std::vector<grpc_message> response_grpc_messages;

    static std::vector<grpc_message> parse_grpc_frames(const std::vector<uint8_t>& body) {
        std::vector<grpc_message> messages;
        size_t pos = 0;
        while (pos + 5 <= body.size()) {
            grpc_message msg;
            msg.compressed = (body[pos] != 0);
            msg.length = (static_cast<uint32_t>(body[pos + 1]) << 24)
                       | (static_cast<uint32_t>(body[pos + 2]) << 16)
                       | (static_cast<uint32_t>(body[pos + 3]) << 8)
                       | static_cast<uint32_t>(body[pos + 4]);
            pos += 5;
            if (pos + msg.length > body.size()) break;
            msg.payload.assign(body.begin() + static_cast<ptrdiff_t>(pos),
                               body.begin() + static_cast<ptrdiff_t>(pos + msg.length));
            pos += msg.length;
            messages.push_back(std::move(msg));
        }
        return messages;
    }
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
        , body_sources_(std::move(other.body_sources_))
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
            body_sources_ = std::move(other.body_sources_);
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
        diag::log_tagged_fmt("h2_session", "initialize role=%s", role_ == role::server ? "server" : "client");

        nghttp2_session_callbacks* callbacks = nullptr;
        int cb_rv = nghttp2_session_callbacks_new(&callbacks);
        if (cb_rv != 0 || !callbacks) {
            diag::log_tagged_fmt("h2_session", "initialize callbacks_new_failed role=%s rv=%d", role_ == role::server ? "server" : "client", cb_rv);
            return false;
        }

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

        if (rv != 0) {
            diag::log_tagged_fmt("h2_session", "initialize session_new_failed role=%s rv=%d", role_ == role::server ? "server" : "client", rv);
            return false;
        }


        nghttp2_settings_entry iv[] = {
            { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
            { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535 }
        };
        rv = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, iv, 2);
        if (rv != 0) {
            diag::log_tagged_fmt("h2_session", "initialize submit_settings_failed role=%s rv=%d", role_ == role::server ? "server" : "client", rv);
            return false;
        }

        ssize_t flush_rv = flush_send();
        diag::log_tagged_fmt("h2_session", "initialize complete role=%s flush=%lld want_read=%d want_write=%d",
            role_ == role::server ? "server" : "client",
            static_cast<long long>(flush_rv),
            nghttp2_session_want_read(session_) != 0,
            nghttp2_session_want_write(session_) != 0);
        return flush_rv >= 0;
    }

    void set_on_request(on_request_t cb)  { on_request_  = std::move(cb); }
    void set_on_response(on_response_t cb) { on_response_ = std::move(cb); }


    ssize_t feed(const uint8_t* data, size_t len) {
        auto rv = nghttp2_session_mem_recv2(session_, data, len);
        diag::log_tagged_fmt("h2_session", "feed role=%s len=%zu rv=%lld streams=%zu",
            role_ == role::server ? "server" : "client",
            len,
            static_cast<long long>(rv),
            streams_.size());
        if (rv < 0) return -1;
        if (flush_send() < 0) {
            diag::log_tagged_fmt("h2_session", "feed flush_failed role=%s", role_ == role::server ? "server" : "client");
            return -1;
        }
        return static_cast<ssize_t>(rv);
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
            nv.flags = NGHTTP2_NV_FLAG_NONE;
            nva.push_back(nv);
        };

        push_nv(":method", method);
        push_nv(":path", path);
        push_nv(":scheme", scheme);
        push_nv(":authority", authority);

        for (auto& h : headers) push_nv(h.name, h.value);

        nghttp2_data_provider prd{};
        std::shared_ptr<body_source> src;
        if (!body.empty()) {
            src = std::make_shared<body_source>();
            src->data = body;
            src->pos = 0;
            prd.source.ptr = src.get();
            prd.read_callback = body_read_callback;
        }

        int32_t stream_id = nghttp2_submit_request(session_, nullptr,
            nva.data(), nva.size(),
            body.empty() ? nullptr : &prd, nullptr);

        if (stream_id < 0) {
            diag::log_tagged_fmt("h2_session", "submit_request failed rv=%d method=%s path_len=%zu authority_len=%zu headers=%zu body=%zu",
                stream_id,
                method.c_str(),
                path.size(),
                authority.size(),
                headers.size(),
                body.size());
            return -1;
        }
        if (src) body_sources_[stream_id] = std::move(src);
        diag::log_tagged_fmt("h2_session", "submit_request stream=%d method=%s path_len=%zu authority_len=%zu headers=%zu body=%zu source_retained=%d",
            stream_id,
            method.c_str(),
            path.size(),
            authority.size(),
            headers.size(),
            body.size(),
            body_sources_.find(stream_id) != body_sources_.end());

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
        status_nv.flags = NGHTTP2_NV_FLAG_NONE;
        nva.push_back(status_nv);

        for (auto& h : headers) {
            nghttp2_nv nv;
            nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(h.name.data()));
            nv.namelen = h.name.size();
            nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(h.value.data()));
            nv.valuelen = h.value.size();
            nv.flags = NGHTTP2_NV_FLAG_NONE;
            nva.push_back(nv);
        }

        nghttp2_data_provider prd{};
        std::shared_ptr<body_source> src;
        if (!body.empty()) {
            src = std::make_shared<body_source>();
            src->data = body;
            src->pos = 0;
            prd.source.ptr = src.get();
            prd.read_callback = body_read_callback;
        }

        int rv = nghttp2_submit_response(session_, stream_id,
            nva.data(), nva.size(),
            body.empty() ? nullptr : &prd);

        if (rv != 0) {
            diag::log_tagged_fmt("h2_session", "submit_response failed stream=%d status=%d rv=%d headers=%zu body=%zu",
                stream_id,
                status_code,
                rv,
                headers.size(),
                body.size());
            return false;
        }
        if (src) body_sources_[stream_id] = std::move(src);
        diag::log_tagged_fmt("h2_session", "submit_response stream=%d status=%d headers=%zu body=%zu source_retained=%d",
            stream_id,
            status_code,
            headers.size(),
            body.size(),
            body_sources_.find(stream_id) != body_sources_.end());
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
    struct body_source {
        std::vector<uint8_t> data;
        size_t pos = 0;
    };

    role                          role_;
    nghttp2_session*              session_ = nullptr;
    std::map<int32_t, stream_data> streams_;
    std::map<int32_t, std::shared_ptr<body_source>> body_sources_;
    send_callback_t               send_cb_;
    on_request_t                  on_request_;
    on_response_t                 on_response_;


    static ssize_t body_read_callback(nghttp2_session* , int32_t ,
                                      uint8_t* buf, size_t length,
                                      uint32_t* data_flags,
                                      nghttp2_data_source* source,
                                      void* ) {
        auto* src = static_cast<body_source*>(source->ptr);
        size_t remaining = src->data.size() - src->pos;
        size_t to_copy = (std::min)(remaining, length);
        if (to_copy > 0) {
            memcpy(buf, src->data.data() + src->pos, to_copy);
            src->pos += to_copy;
        }
        if (src->pos >= src->data.size()) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        diag::log_tagged_fmt("h2_session", "body_read requested=%zu copied=%zu pos=%zu total=%zu eof=%d",
            length,
            to_copy,
            src->pos,
            src->data.size(),
            (*data_flags & NGHTTP2_DATA_FLAG_EOF) != 0);
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
            diag::log_tagged_fmt("h2_session", "begin_headers role=%s stream=%d cat=%d",
                self->role_ == role::server ? "server" : "client",
                frame->hd.stream_id,
                static_cast<int>(frame->headers.cat));
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


        if (n == ":method")    {
            sd.method = v;
            diag::log_tagged_fmt("h2_session", "pseudo_header role=%s stream=%d name=:method value_len=%zu",
                self->role_ == role::server ? "server" : "client", frame->hd.stream_id, v.size());
            return 0;
        }
        if (n == ":path")      {
            sd.path = v;
            diag::log_tagged_fmt("h2_session", "pseudo_header role=%s stream=%d name=:path value_len=%zu",
                self->role_ == role::server ? "server" : "client", frame->hd.stream_id, v.size());
            return 0;
        }
        if (n == ":authority") {
            sd.authority = v;
            diag::log_tagged_fmt("h2_session", "pseudo_header role=%s stream=%d name=:authority value_len=%zu",
                self->role_ == role::server ? "server" : "client", frame->hd.stream_id, v.size());
            return 0;
        }
        if (n == ":scheme")    {
            sd.scheme = v;
            diag::log_tagged_fmt("h2_session", "pseudo_header role=%s stream=%d name=:scheme value_len=%zu",
                self->role_ == role::server ? "server" : "client", frame->hd.stream_id, v.size());
            return 0;
        }
        if (n == ":status")    {
            char* end = nullptr;
            errno = 0;
            long code = strtol(v.c_str(), &end, 10);
            if (errno == 0 && end != v.c_str() && code >= 100 && code <= 999) {
                sd.status_code = static_cast<int>(code);
            }
            diag::log_tagged_fmt("h2_session", "pseudo_header role=%s stream=%d name=:status value_len=%zu status=%d",
                self->role_ == role::server ? "server" : "client",
                frame->hd.stream_id,
                v.size(),
                sd.status_code);
            return 0;
        }


        protocol_parser::http_header hdr;
        hdr.name  = std::move(n);
        hdr.value = std::move(v);
        diag::log_tagged_fmt("h2_session", "header role=%s stream=%d cat=%d name=%s value_len=%zu",
            self->role_ == role::server ? "server" : "client",
            frame->hd.stream_id,
            static_cast<int>(frame->headers.cat),
            hdr.name.c_str(),
            hdr.value.size());


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
            diag::log_tagged_fmt("h2_session", "data_chunk request stream=%d len=%zu total=%zu",
                stream_id,
                len,
                sd.request_body.size());
        } else {
            sd.response_body.insert(sd.response_body.end(), data, data + len);
            diag::log_tagged_fmt("h2_session", "data_chunk response stream=%d len=%zu total=%zu",
                stream_id,
                len,
                sd.response_body.size());
        }
        return 0;
    }

    static int on_frame_recv(nghttp2_session* ,
                             const nghttp2_frame* frame, void* user_data) {
        auto* self = static_cast<session*>(user_data);

        if (frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) {
            diag::log_tagged_fmt("h2_session", "frame_recv role=%s stream=%d type=%d flags=0x%02x",
                self->role_ == role::server ? "server" : "client",
                frame->hd.stream_id,
                static_cast<int>(frame->hd.type),
                frame->hd.flags);
            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                auto it = self->streams_.find(frame->hd.stream_id);
                if (it != self->streams_.end()) {
                    auto& sd = it->second;
                    if (self->role_ == role::server && !sd.request_complete) {
                        sd.request_complete = true;
                        if (sd.is_grpc && !sd.request_body.empty()) {
                            sd.request_grpc_messages = stream_data::parse_grpc_frames(sd.request_body);
                        }
                        if (self->on_request_) self->on_request_(sd);
                        diag::log_tagged_fmt("h2_session", "request_complete stream=%d headers=%zu body=%zu grpc=%d",
                            frame->hd.stream_id,
                            sd.request_headers.size(),
                            sd.request_body.size(),
                            static_cast<int>(sd.is_grpc));
                    } else {
                        sd.response_complete = true;
                        if (sd.is_grpc && !sd.response_body.empty()) {
                            sd.response_grpc_messages = stream_data::parse_grpc_frames(sd.response_body);
                        }
                        if (self->on_response_) self->on_response_(sd);
                        diag::log_tagged_fmt("h2_session", "response_complete stream=%d status=%d headers=%zu body=%zu grpc=%d",
                            frame->hd.stream_id,
                            sd.status_code,
                            sd.response_headers.size(),
                            sd.response_body.size(),
                            static_cast<int>(sd.is_grpc));
                    }
                }
            }
        }
        return 0;
    }

    static int on_stream_close(nghttp2_session* , int32_t stream_id,
                               uint32_t , void* user_data) {
        auto* self = static_cast<session*>(user_data);

        self->body_sources_.erase(stream_id);
        diag::log_tagged_fmt("h2_session", "stream_close role=%s stream=%d sources_remaining=%zu",
            self->role_ == role::server ? "server" : "client",
            stream_id,
            self->body_sources_.size());
        return 0;
    }
};

}
