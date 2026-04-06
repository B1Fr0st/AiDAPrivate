#pragma once


#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <zlib.h>
#include <brotli/decode.h>
#include <brotli/encode.h>

namespace decoder_pipeline {


struct transform_param {
    std::string name;
    std::string label;
    std::string default_value;
    enum class type_t { text, hex_bytes, integer, choice } type = type_t::text;
    std::vector<std::string> choices;
};


struct transform_result {
    bool success = false;
    std::vector<uint8_t> data;
    std::string error;
};


struct transform_def {
    std::string id;
    std::string name;
    std::string category;
    std::vector<transform_param> params;
    std::function<transform_result(const std::vector<uint8_t>& input,
                                   const std::map<std::string, std::string>& params)> execute;
};


struct pipeline_step {
    std::string transform_id;
    std::map<std::string, std::string> param_values;
    bool enabled = true;
};


struct pipeline {
    std::vector<pipeline_step> steps;
    std::string name;
};


static std::vector<uint8_t> hex_decode(const std::string& hex);
static std::string hex_encode(const uint8_t* data, size_t len);


class registry {
public:
    static registry& instance() {
        static registry inst;
        return inst;
    }

    void register_transform(transform_def def) {
        auto id = def.id;
        transforms_[id] = std::move(def);
        if (std::find(order_.begin(), order_.end(), id) == order_.end())
            order_.push_back(id);
    }

    const transform_def* find(const std::string& id) const {
        auto it = transforms_.find(id);
        return (it != transforms_.end()) ? &it->second : nullptr;
    }

    std::vector<const transform_def*> all() const {
        std::vector<const transform_def*> result;
        for (auto& id : order_) {
            auto it = transforms_.find(id);
            if (it != transforms_.end()) result.push_back(&it->second);
        }
        return result;
    }

    std::vector<const transform_def*> by_category(const std::string& category) const {
        std::vector<const transform_def*> result;
        for (auto& id : order_) {
            auto it = transforms_.find(id);
            if (it != transforms_.end() && it->second.category == category)
                result.push_back(&it->second);
        }
        return result;
    }

    std::vector<std::string> categories() const {
        std::vector<std::string> cats;
        for (auto& id : order_) {
            auto it = transforms_.find(id);
            if (it != transforms_.end()) {
                auto& c = it->second.category;
                if (std::find(cats.begin(), cats.end(), c) == cats.end())
                    cats.push_back(c);
            }
        }
        return cats;
    }

private:
    registry() { register_builtins(); }
    void register_builtins();

    std::map<std::string, transform_def> transforms_;
    std::vector<std::string> order_;
};


inline transform_result execute_pipeline(const pipeline& pipe,
                                         const std::vector<uint8_t>& input) {
    auto& reg = registry::instance();
    std::vector<uint8_t> data = input;

    for (auto& step : pipe.steps) {
        if (!step.enabled) continue;
        auto* def = reg.find(step.transform_id);
        if (!def) return { false, {}, "Unknown transform: " + step.transform_id };


        std::map<std::string, std::string> merged;
        for (auto& p : def->params)
            merged[p.name] = p.default_value;
        for (auto& [k, v] : step.param_values)
            merged[k] = v;

        auto result = def->execute(data, merged);
        if (!result.success) return result;
        data = std::move(result.data);
    }

    return { true, std::move(data), {} };
}


inline transform_result apply_single(const std::string& transform_id,
                                     const std::vector<uint8_t>& input,
                                     const std::map<std::string, std::string>& params = {}) {
    pipeline pipe;
    pipe.steps.push_back({ transform_id, params, true });
    return execute_pipeline(pipe, input);
}


static std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {

        while (i < hex.size() && (hex[i] == ' ' || hex[i] == ':' || hex[i] == '\n' || hex[i] == '\r'))
            ++i;
        if (i + 1 >= hex.size()) break;
        char byte_str[3] = { hex[i], hex[i + 1], 0 };
        char* end = nullptr;
        unsigned long val = strtoul(byte_str, &end, 16);
        if (end != byte_str + 2) break;
        out.push_back(static_cast<uint8_t>(val));
    }
    return out;
}

static std::string hex_encode(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += hex_chars[(data[i] >> 4) & 0xF];
        out += hex_chars[data[i] & 0xF];
    }
    return out;
}


static std::vector<uint8_t> base64_decode_impl(const std::vector<uint8_t>& input) {

    std::string cleaned;
    cleaned.reserve(input.size());
    for (auto c : input) {
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
            cleaned += static_cast<char>(c);
    }

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf(cleaned.data(), static_cast<int>(cleaned.size()));
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

    std::vector<uint8_t> out(cleaned.size());
    int decoded_len = BIO_read(bmem, out.data(), static_cast<int>(out.size()));
    BIO_free_all(bmem);

    if (decoded_len < 0) return {};
    out.resize(static_cast<size_t>(decoded_len));
    return out;
}

static std::string base64_encode_impl(const uint8_t* data, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, static_cast<int>(len));
    BIO_flush(b64);

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(b64);
    return out;
}


static std::string url_encode_impl(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(len * 3);
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = data[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += hex_chars[(c >> 4) & 0xF];
            out += hex_chars[c & 0xF];
        }
    }
    return out;
}

static std::vector<uint8_t> url_decode_impl(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> out;
    out.reserve(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '%' && i + 2 < input.size()) {
            char byte_str[3] = { static_cast<char>(input[i+1]),
                                 static_cast<char>(input[i+2]), 0 };
            char* end = nullptr;
            unsigned long val = strtoul(byte_str, &end, 16);
            if (end == byte_str + 2) {
                out.push_back(static_cast<uint8_t>(val));
                i += 2;
                continue;
            }
        }
        if (input[i] == '+') {
            out.push_back(' ');
        } else {
            out.push_back(input[i]);
        }
    }
    return out;
}


static std::vector<uint8_t> gzip_decompress(const std::vector<uint8_t>& input) {
    z_stream strm = {};

    if (inflateInit2(&strm, 15 + 32) != Z_OK) return {};

    strm.avail_in = static_cast<uInt>(input.size());
    strm.next_in  = const_cast<Bytef*>(input.data());

    std::vector<uint8_t> out;
    out.resize(input.size() * 4);

    int ret;
    do {
        if (out.size() - strm.total_out < 4096)
            out.resize(out.size() * 2);
        strm.avail_out = static_cast<uInt>(out.size() - strm.total_out);
        strm.next_out  = out.data() + strm.total_out;
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&strm);
            return {};
        }
    } while (ret != Z_STREAM_END);

    out.resize(strm.total_out);
    inflateEnd(&strm);
    return out;
}

static std::vector<uint8_t> gzip_compress(const std::vector<uint8_t>& input, int level = Z_DEFAULT_COMPRESSION) {
    z_stream strm = {};

    if (deflateInit2(&strm, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return {};

    strm.avail_in = static_cast<uInt>(input.size());
    strm.next_in  = const_cast<Bytef*>(input.data());

    std::vector<uint8_t> out(deflateBound(&strm, strm.avail_in));
    strm.avail_out = static_cast<uInt>(out.size());
    strm.next_out  = out.data();

    deflate(&strm, Z_FINISH);
    out.resize(strm.total_out);
    deflateEnd(&strm);
    return out;
}


static std::vector<uint8_t> brotli_decompress_impl(const std::vector<uint8_t>& input) {
    size_t decoded_size = input.size() * 8;
    std::vector<uint8_t> out(decoded_size);

    BrotliDecoderResult result = BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT;
    const uint8_t* next_in = input.data();
    size_t avail_in = input.size();

    BrotliDecoderState* state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    if (!state) return {};

    std::vector<uint8_t> final_out;
    while (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
        size_t avail_out = out.size();
        uint8_t* next_out = out.data();
        result = BrotliDecoderDecompressStream(state, &avail_in, &next_in,
                                                &avail_out, &next_out, nullptr);
        size_t used = out.size() - avail_out;
        final_out.insert(final_out.end(), out.data(), out.data() + used);
    }

    BrotliDecoderDestroyInstance(state);
    if (result != BROTLI_DECODER_RESULT_SUCCESS) return {};
    return final_out;
}

static std::vector<uint8_t> brotli_compress_impl(const std::vector<uint8_t>& input, int quality = BROTLI_DEFAULT_QUALITY) {
    size_t max_size = BrotliEncoderMaxCompressedSize(input.size());
    std::vector<uint8_t> out(max_size);
    size_t encoded_size = max_size;

    if (!BrotliEncoderCompress(quality, BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE,
                               input.size(), input.data(),
                               &encoded_size, out.data()))
        return {};

    out.resize(encoded_size);
    return out;
}


static std::vector<uint8_t> xor_transform(const std::vector<uint8_t>& input,
                                           const std::vector<uint8_t>& key) {
    if (key.empty()) return input;
    std::vector<uint8_t> out(input.size());
    for (size_t i = 0; i < input.size(); ++i)
        out[i] = input[i] ^ key[i % key.size()];
    return out;
}


static transform_result aes_operation(const std::vector<uint8_t>& input,
                                      const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& iv,
                                      const std::string& mode,
                                      bool encrypt) {
    const EVP_CIPHER* cipher = nullptr;
    if (key.size() == 16) {
        if (mode == "CBC") cipher = EVP_aes_128_cbc();
        else if (mode == "CTR") cipher = EVP_aes_128_ctr();
        else if (mode == "ECB") cipher = EVP_aes_128_ecb();
        else if (mode == "GCM") cipher = EVP_aes_128_gcm();
    } else if (key.size() == 24) {
        if (mode == "CBC") cipher = EVP_aes_192_cbc();
        else if (mode == "CTR") cipher = EVP_aes_192_ctr();
        else if (mode == "ECB") cipher = EVP_aes_192_ecb();
        else if (mode == "GCM") cipher = EVP_aes_192_gcm();
    } else if (key.size() == 32) {
        if (mode == "CBC") cipher = EVP_aes_256_cbc();
        else if (mode == "CTR") cipher = EVP_aes_256_ctr();
        else if (mode == "ECB") cipher = EVP_aes_256_ecb();
        else if (mode == "GCM") cipher = EVP_aes_256_gcm();
    }

    if (!cipher) return { false, {}, "Invalid AES key size (" + std::to_string(key.size()) + ") or mode (" + mode + ")" };

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return { false, {}, "EVP_CIPHER_CTX_new failed" };


    std::vector<uint8_t> out(input.size() + EVP_CIPHER_block_size(cipher) + 16);
    int out_len = 0, final_len = 0;

    int ok;
    if (encrypt) {
        ok = EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(),
                                iv.empty() ? nullptr : iv.data());
    } else {
        ok = EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(),
                                iv.empty() ? nullptr : iv.data());
    }

    if (!ok) {
        EVP_CIPHER_CTX_free(ctx);
        return { false, {}, "EVP init failed" };
    }

    if (encrypt) {
        EVP_EncryptUpdate(ctx, out.data(), &out_len,
                          input.data(), static_cast<int>(input.size()));
        EVP_EncryptFinal_ex(ctx, out.data() + out_len, &final_len);
    } else {
        EVP_DecryptUpdate(ctx, out.data(), &out_len,
                          input.data(), static_cast<int>(input.size()));
        if (!EVP_DecryptFinal_ex(ctx, out.data() + out_len, &final_len)) {
            EVP_CIPHER_CTX_free(ctx);
            return { false, {}, "AES decryption failed (padding error?)" };
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    out.resize(static_cast<size_t>(out_len + final_len));
    return { true, std::move(out), {} };
}


static std::vector<uint8_t> hash_data(const std::vector<uint8_t>& input, const std::string& algo) {
    const EVP_MD* md = EVP_get_digestbyname(algo.c_str());
    if (!md) return {};

    unsigned int md_len = 0;
    std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, out.data(), &md_len);
    EVP_MD_CTX_free(ctx);
    out.resize(md_len);
    return out;
}


static std::vector<uint8_t> hmac_data(const std::vector<uint8_t>& input,
                                      const std::vector<uint8_t>& key,
                                      const std::string& algo) {
    const EVP_MD* md = EVP_get_digestbyname(algo.c_str());
    if (!md) return {};

    unsigned int md_len = 0;
    std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
    HMAC(md, key.data(), static_cast<int>(key.size()),
         input.data(), input.size(), out.data(), &md_len);
    out.resize(md_len);
    return out;
}


static std::string json_beautify(const std::string& input) {
    std::string out;
    out.reserve(input.size() * 2);
    int indent = 0;
    bool in_string = false;
    bool escaped = false;

    auto add_indent = [&]() {
        for (int i = 0; i < indent; ++i) out += "  ";
    };

    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];

        if (escaped) { out += c; escaped = false; continue; }
        if (c == '\\' && in_string) { out += c; escaped = true; continue; }
        if (c == '"') { out += c; in_string = !in_string; continue; }
        if (in_string) { out += c; continue; }


        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;

        if (c == '{' || c == '[') {
            out += c;
            out += '\n';
            ++indent;
            add_indent();
        } else if (c == '}' || c == ']') {
            out += '\n';
            --indent;
            add_indent();
            out += c;
        } else if (c == ',') {
            out += c;
            out += '\n';
            add_indent();
        } else if (c == ':') {
            out += ": ";
        } else {
            out += c;
        }
    }
    return out;
}


static std::string json_minify(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    bool in_string = false;
    bool escaped = false;

    for (char c : input) {
        if (escaped) { out += c; escaped = false; continue; }
        if (c == '\\' && in_string) { out += c; escaped = true; continue; }
        if (c == '"') { out += c; in_string = !in_string; continue; }
        if (in_string) { out += c; continue; }
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        out += c;
    }
    return out;
}


static std::string html_entity_encode(const std::string& input) {
    std::string out;
    out.reserve(input.size() * 2);
    for (char c : input) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default:   out += c; break;
        }
    }
    return out;
}

static std::string html_entity_decode(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '&') {
            if (input.compare(i, 4, "&lt;") == 0) { out += '<'; i += 3; }
            else if (input.compare(i, 4, "&gt;") == 0) { out += '>'; i += 3; }
            else if (input.compare(i, 5, "&amp;") == 0) { out += '&'; i += 4; }
            else if (input.compare(i, 6, "&quot;") == 0) { out += '"'; i += 5; }
            else if (input.compare(i, 5, "&#39;") == 0) { out += '\''; i += 4; }
            else if (input.compare(i, 6, "&#x27;") == 0) { out += '\''; i += 5; }
            else if (input.compare(i, 5, "&apos;") == 0) { out += '\''; i += 4; }
            else out += input[i];
        } else {
            out += input[i];
        }
    }
    return out;
}


static std::string hex_dump_format(const uint8_t* data, size_t len, size_t bytes_per_line = 16) {
    std::string out;
    for (size_t offset = 0; offset < len; offset += bytes_per_line) {
        char addr[16];
        snprintf(addr, sizeof(addr), "%08zx  ", offset);
        out += addr;

        size_t line_end = (std::min)(offset + bytes_per_line, len);
        for (size_t i = offset; i < offset + bytes_per_line; ++i) {
            if (i < line_end) {
                char byte[4];
                snprintf(byte, sizeof(byte), "%02x ", data[i]);
                out += byte;
            } else {
                out += "   ";
            }
            if (i == offset + bytes_per_line / 2 - 1) out += ' ';
        }

        out += " |";
        for (size_t i = offset; i < line_end; ++i) {
            out += (data[i] >= 32 && data[i] < 127) ? static_cast<char>(data[i]) : '.';
        }
        out += "|\n";
    }
    return out;
}


struct protobuf_field {
    uint32_t field_number = 0;
    uint32_t wire_type = 0;
    uint64_t varint_value = 0;
    std::vector<uint8_t> bytes_value;
    double double_value = 0;
    float float_value = 0;
};

static bool decode_protobuf_varint(const uint8_t* data, size_t len, size_t& pos, uint64_t& value) {
    value = 0;
    unsigned shift = 0;
    while (pos < len && shift < 64) {
        uint8_t b = data[pos++];
        value |= static_cast<uint64_t>(b & 0x7F) << shift;
        if (!(b & 0x80)) return true;
        shift += 7;
    }
    return false;
}

static std::vector<protobuf_field> decode_protobuf_wire(const uint8_t* data, size_t len) {
    std::vector<protobuf_field> fields;
    size_t pos = 0;

    while (pos < len) {
        uint64_t tag = 0;
        if (!decode_protobuf_varint(data, len, pos, tag)) break;

        protobuf_field f;
        f.field_number = static_cast<uint32_t>(tag >> 3);
        f.wire_type = static_cast<uint32_t>(tag & 0x7);

        switch (f.wire_type) {
            case 0:
                if (!decode_protobuf_varint(data, len, pos, f.varint_value)) return fields;
                break;
            case 1:
                if (pos + 8 > len) return fields;
                memcpy(&f.double_value, data + pos, 8);
                memcpy(&f.varint_value, data + pos, 8);
                pos += 8;
                break;
            case 2: {
                uint64_t length = 0;
                if (!decode_protobuf_varint(data, len, pos, length)) return fields;
                if (pos + length > len) return fields;
                f.bytes_value.assign(data + pos, data + pos + length);
                pos += static_cast<size_t>(length);
                break;
            }
            case 5:
                if (pos + 4 > len) return fields;
                memcpy(&f.float_value, data + pos, 4);
                memcpy(&f.varint_value, data + pos, 4);
                f.varint_value &= 0xFFFFFFFF;
                pos += 4;
                break;
            default:
                return fields;
        }
        fields.push_back(std::move(f));
    }
    return fields;
}

static std::string protobuf_to_text(const std::vector<protobuf_field>& fields, int indent = 0) {
    std::string out;
    std::string pad(indent * 2, ' ');

    for (auto& f : fields) {
        out += pad + "field " + std::to_string(f.field_number) + " [wire " + std::to_string(f.wire_type) + "]: ";
        switch (f.wire_type) {
            case 0:
                out += std::to_string(f.varint_value);

                {
                    // WHY: -(uint64_t) triggers MSVC C4146 (unary minus on unsigned).
                    // uint64_t(0)-(x) is identical bit-pattern (0 or 0xFFFFFFFFFFFFFFFF)
                    // via well-defined unsigned wraparound — no truncation, no warning.
                    int64_t zigzag = static_cast<int64_t>((f.varint_value >> 1) ^ (uint64_t(0) - (f.varint_value & 1)));
                    if (zigzag != static_cast<int64_t>(f.varint_value))
                        out += " (zigzag: " + std::to_string(zigzag) + ")";
                }
                break;
            case 1:
                out += "0x" + hex_encode(reinterpret_cast<const uint8_t*>(&f.varint_value), 8);
                out += " (double: " + std::to_string(f.double_value) + ")";
                break;
            case 2: {

                auto nested = decode_protobuf_wire(f.bytes_value.data(), f.bytes_value.size());
                if (!nested.empty() && nested.size() > 0) {

                    bool valid = true;
                    for (auto& nf : nested)
                        if (nf.field_number == 0) { valid = false; break; }

                    if (valid && nested.size() > 1) {
                        out += "{\n";
                        out += protobuf_to_text(nested, indent + 1);
                        out += pad + "}";
                    } else {

                        bool printable = true;
                        for (auto b : f.bytes_value) {
                            if (b < 0x20 && b != '\n' && b != '\r' && b != '\t') {
                                printable = false;
                                break;
                            }
                        }
                        if (printable && !f.bytes_value.empty()) {
                            out += "\"" + std::string(f.bytes_value.begin(), f.bytes_value.end()) + "\"";
                        } else {
                            out += hex_encode(f.bytes_value.data(), f.bytes_value.size());
                        }
                        out += " (" + std::to_string(f.bytes_value.size()) + " bytes)";
                    }
                } else {
                    bool printable = true;
                    for (auto b : f.bytes_value) {
                        if (b < 0x20 && b != '\n' && b != '\r' && b != '\t') {
                            printable = false;
                            break;
                        }
                    }
                    if (printable && !f.bytes_value.empty()) {
                        out += "\"" + std::string(f.bytes_value.begin(), f.bytes_value.end()) + "\"";
                    } else {
                        out += hex_encode(f.bytes_value.data(), f.bytes_value.size());
                    }
                    out += " (" + std::to_string(f.bytes_value.size()) + " bytes)";
                }
                break;
            }
            case 5:
                out += "0x" + hex_encode(reinterpret_cast<const uint8_t*>(&f.varint_value), 4);
                out += " (float: " + std::to_string(f.float_value) + ")";
                break;
        }
        out += "\n";
    }
    return out;
}

// Encode a varint to the back of a byte buffer.
static inline void encode_varint(std::vector<uint8_t>& buf, uint64_t v) {
    while (v > 0x7F) {
        buf.push_back(static_cast<uint8_t>((v & 0x7F) | 0x80));
        v >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(v & 0x7F));
}

// Encode a list of protobuf fields back to Protobuf wire format.
static std::vector<uint8_t> protobuf_encode(const std::vector<protobuf_field>& fields) {
    std::vector<uint8_t> out;
    for (auto& f : fields) {
        uint64_t tag = (static_cast<uint64_t>(f.field_number) << 3) |
                       (static_cast<uint64_t>(f.wire_type) & 0x7);
        encode_varint(out, tag);
        switch (f.wire_type) {
            case 0: // varint
                encode_varint(out, f.varint_value);
                break;
            case 1: { // 64-bit
                uint64_t v = f.varint_value;
                for (int i = 0; i < 8; i++) {
                    out.push_back(static_cast<uint8_t>(v & 0xFF));
                    v >>= 8;
                }
                break;
            }
            case 2: // length-delimited
                encode_varint(out, f.bytes_value.size());
                out.insert(out.end(), f.bytes_value.begin(), f.bytes_value.end());
                break;
            case 5: { // 32-bit
                uint32_t v = static_cast<uint32_t>(f.varint_value & 0xFFFFFFFF);
                for (int i = 0; i < 4; i++) {
                    out.push_back(static_cast<uint8_t>(v & 0xFF));
                    v >>= 8;
                }
                break;
            }
            default:
                break;
        }
    }
    return out;
}

// Wrap raw protobuf bytes with a 5-byte gRPC frame header:
//   [0x00][len_hi][len_lo2][len_lo1][len_lo0]
static std::vector<uint8_t> grpc_encode(const std::vector<uint8_t>& proto_bytes) {
    std::vector<uint8_t> out;
    out.reserve(5 + proto_bytes.size());
    uint32_t len = static_cast<uint32_t>(proto_bytes.size());
    out.push_back(0x00); // not compressed
    out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((len >>  8) & 0xFF));
    out.push_back(static_cast<uint8_t>( len        & 0xFF));
    out.insert(out.end(), proto_bytes.begin(), proto_bytes.end());
    return out;
}


inline void registry::register_builtins() {


    register_transform({
        "base64_encode", "Base64 Encode", "Encoding", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            auto enc = base64_encode_impl(input.data(), input.size());
            return { true, std::vector<uint8_t>(enc.begin(), enc.end()), {} };
        }
    });

    register_transform({
        "base64_decode", "Base64 Decode", "Encoding", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            auto dec = base64_decode_impl(input);
            if (dec.empty() && !input.empty()) return { false, {}, "Invalid Base64 input" };
            return { true, std::move(dec), {} };
        }
    });

    register_transform({
        "hex_encode", "To Hex", "Encoding", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            auto enc = hex_encode(input.data(), input.size());
            return { true, std::vector<uint8_t>(enc.begin(), enc.end()), {} };
        }
    });

    register_transform({
        "hex_decode", "From Hex", "Encoding", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            std::string hex_str(input.begin(), input.end());
            auto dec = hex_decode(hex_str);
            return { true, std::move(dec), {} };
        }
    });

    register_transform({
        "url_encode", "URL Encode", "Encoding", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            auto enc = url_encode_impl(input.data(), input.size());
            return { true, std::vector<uint8_t>(enc.begin(), enc.end()), {} };
        }
    });

    register_transform({
        "url_decode", "URL Decode", "Encoding", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            auto dec = url_decode_impl(input);
            return { true, std::move(dec), {} };
        }
    });

    register_transform({
        "html_encode", "HTML Entity Encode", "Encoding", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            std::string s(input.begin(), input.end());
            auto enc = html_entity_encode(s);
            return { true, std::vector<uint8_t>(enc.begin(), enc.end()), {} };
        }
    });

    register_transform({
        "html_decode", "HTML Entity Decode", "Encoding", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            std::string s(input.begin(), input.end());
            auto dec = html_entity_decode(s);
            return { true, std::vector<uint8_t>(dec.begin(), dec.end()), {} };
        }
    });


    register_transform({
        "gzip_decompress", "Gunzip", "Compression", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            auto dec = gzip_decompress(input);
            if (dec.empty() && !input.empty()) return { false, {}, "Gzip decompression failed" };
            return { true, std::move(dec), {} };
        }
    });

    register_transform({
        "gzip_compress", "Gzip", "Compression",
        { { "level", "Compression level", "6", transform_param::type_t::choice, {"1","2","3","4","5","6","7","8","9"} } },
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>& params) -> transform_result {
            int level = Z_DEFAULT_COMPRESSION;
            auto it = params.find("level");
            if (it != params.end()) level = std::stoi(it->second);
            auto enc = gzip_compress(input, level);
            if (enc.empty() && !input.empty()) return { false, {}, "Gzip compression failed" };
            return { true, std::move(enc), {} };
        }
    });

    register_transform({
        "brotli_decompress", "Brotli Decompress", "Compression", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            auto dec = brotli_decompress_impl(input);
            if (dec.empty() && !input.empty()) return { false, {}, "Brotli decompression failed" };
            return { true, std::move(dec), {} };
        }
    });

    register_transform({
        "brotli_compress", "Brotli Compress", "Compression",
        { { "quality", "Quality", "6", transform_param::type_t::choice, {"1","2","3","4","5","6","7","8","9","10","11"} } },
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>& params) -> transform_result {
            int quality = BROTLI_DEFAULT_QUALITY;
            auto it = params.find("quality");
            if (it != params.end()) quality = std::stoi(it->second);
            auto enc = brotli_compress_impl(input, quality);
            if (enc.empty() && !input.empty()) return { false, {}, "Brotli compression failed" };
            return { true, std::move(enc), {} };
        }
    });

    register_transform({
        "deflate_decompress", "Inflate (raw deflate)", "Compression", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            z_stream strm = {};
            if (inflateInit2(&strm, -15) != Z_OK) return { false, {}, "inflateInit failed" };
            strm.avail_in = static_cast<uInt>(input.size());
            strm.next_in = const_cast<Bytef*>(input.data());
            std::vector<uint8_t> out(input.size() * 4);
            int ret;
            do {
                if (out.size() - strm.total_out < 4096) out.resize(out.size() * 2);
                strm.avail_out = static_cast<uInt>(out.size() - strm.total_out);
                strm.next_out = out.data() + strm.total_out;
                ret = inflate(&strm, Z_NO_FLUSH);
                if (ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) { inflateEnd(&strm); return { false, {}, "Inflate failed" }; }
            } while (ret != Z_STREAM_END);
            out.resize(strm.total_out);
            inflateEnd(&strm);
            return { true, std::move(out), {} };
        }
    });


    register_transform({
        "xor", "XOR", "Crypto",
        { { "key", "Key (hex)", "00", transform_param::type_t::hex_bytes, {} } },
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>& params) -> transform_result {
            auto it = params.find("key");
            if (it == params.end() || it->second.empty()) return { false, {}, "XOR key required" };
            auto key = hex_decode(it->second);
            if (key.empty()) return { false, {}, "Invalid hex key" };
            return { true, xor_transform(input, key), {} };
        }
    });

    register_transform({
        "aes_encrypt", "AES Encrypt", "Crypto",
        {
            { "key", "Key (hex)", "", transform_param::type_t::hex_bytes, {} },
            { "iv", "IV (hex)", "", transform_param::type_t::hex_bytes, {} },
            { "mode", "Mode", "CBC", transform_param::type_t::choice, {"CBC","CTR","ECB","GCM"} }
        },
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>& params) -> transform_result {
            auto ki = params.find("key");
            auto ii = params.find("iv");
            auto mi = params.find("mode");
            if (ki == params.end() || ki->second.empty()) return { false, {}, "AES key required" };
            auto key = hex_decode(ki->second);
            auto iv  = (ii != params.end() && !ii->second.empty()) ? hex_decode(ii->second) : std::vector<uint8_t>{};
            std::string mode = (mi != params.end()) ? mi->second : "CBC";
            return aes_operation(input, key, iv, mode, true);
        }
    });

    register_transform({
        "aes_decrypt", "AES Decrypt", "Crypto",
        {
            { "key", "Key (hex)", "", transform_param::type_t::hex_bytes, {} },
            { "iv", "IV (hex)", "", transform_param::type_t::hex_bytes, {} },
            { "mode", "Mode", "CBC", transform_param::type_t::choice, {"CBC","CTR","ECB","GCM"} }
        },
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>& params) -> transform_result {
            auto ki = params.find("key");
            auto ii = params.find("iv");
            auto mi = params.find("mode");
            if (ki == params.end() || ki->second.empty()) return { false, {}, "AES key required" };
            auto key = hex_decode(ki->second);
            auto iv  = (ii != params.end() && !ii->second.empty()) ? hex_decode(ii->second) : std::vector<uint8_t>{};
            std::string mode = (mi != params.end()) ? mi->second : "CBC";
            return aes_operation(input, key, iv, mode, false);
        }
    });


    register_transform({
        "md5", "MD5", "Hashing", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            auto h = hash_data(input, "md5");
            auto hex = hex_encode(h.data(), h.size());
            return { true, std::vector<uint8_t>(hex.begin(), hex.end()), {} };
        }
    });

    register_transform({
        "sha1", "SHA-1", "Hashing", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            auto h = hash_data(input, "sha1");
            auto hex = hex_encode(h.data(), h.size());
            return { true, std::vector<uint8_t>(hex.begin(), hex.end()), {} };
        }
    });

    register_transform({
        "sha256", "SHA-256", "Hashing", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            auto h = hash_data(input, "sha256");
            auto hex = hex_encode(h.data(), h.size());
            return { true, std::vector<uint8_t>(hex.begin(), hex.end()), {} };
        }
    });

    register_transform({
        "sha512", "SHA-512", "Hashing", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            auto h = hash_data(input, "sha512");
            auto hex = hex_encode(h.data(), h.size());
            return { true, std::vector<uint8_t>(hex.begin(), hex.end()), {} };
        }
    });

    register_transform({
        "hmac", "HMAC", "Hashing",
        {
            { "key", "Key (hex)", "", transform_param::type_t::hex_bytes, {} },
            { "algo", "Algorithm", "sha256", transform_param::type_t::choice, {"md5","sha1","sha256","sha512"} }
        },
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>& params) -> transform_result {
            auto ki = params.find("key");
            auto ai = params.find("algo");
            if (ki == params.end() || ki->second.empty()) return { false, {}, "HMAC key required" };
            auto key = hex_decode(ki->second);
            std::string algo = (ai != params.end()) ? ai->second : "sha256";
            auto h = hmac_data(input, key, algo);
            auto hex = hex_encode(h.data(), h.size());
            return { true, std::vector<uint8_t>(hex.begin(), hex.end()), {} };
        }
    });


    register_transform({
        "json_beautify", "JSON Beautify", "Formatting", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            std::string s(input.begin(), input.end());
            auto beautified = json_beautify(s);
            return { true, std::vector<uint8_t>(beautified.begin(), beautified.end()), {} };
        }
    });

    register_transform({
        "json_minify", "JSON Minify", "Formatting", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            std::string s(input.begin(), input.end());
            auto minified = json_minify(s);
            return { true, std::vector<uint8_t>(minified.begin(), minified.end()), {} };
        }
    });

    register_transform({
        "hex_dump", "Hex Dump", "Formatting",
        { { "width", "Bytes per line", "16", transform_param::type_t::integer, {} } },
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>& params) -> transform_result {
            size_t width = 16;
            auto it = params.find("width");
            if (it != params.end()) {
                int w = std::stoi(it->second);
                if (w > 0 && w <= 64) width = static_cast<size_t>(w);
            }
            auto dump = hex_dump_format(input.data(), input.size(), width);
            return { true, std::vector<uint8_t>(dump.begin(), dump.end()), {} };
        }
    });


    register_transform({
        "protobuf_decode", "Protobuf Decode", "Protocol", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            auto fields = decode_protobuf_wire(input.data(), input.size());
            if (fields.empty() && !input.empty()) return { false, {}, "Not valid protobuf data" };
            auto text = protobuf_to_text(fields);
            return { true, std::vector<uint8_t>(text.begin(), text.end()), {} };
        }
    });

    register_transform({
        "grpc_decode", "gRPC Decode (length-prefixed protobuf)", "Protocol", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {

            if (input.size() < 5) return { false, {}, "Too short for gRPC frame" };
            bool compressed = (input[0] != 0);
            uint32_t msg_len = (static_cast<uint32_t>(input[1]) << 24)
                             | (static_cast<uint32_t>(input[2]) << 16)
                             | (static_cast<uint32_t>(input[3]) << 8)
                             | static_cast<uint32_t>(input[4]);
            if (5 + msg_len > input.size()) return { false, {}, "gRPC frame truncated" };

            std::vector<uint8_t> payload(input.begin() + 5, input.begin() + 5 + msg_len);
            if (compressed) {
                auto decompressed = gzip_decompress(payload);
                if (!decompressed.empty()) payload = std::move(decompressed);
            }

            auto fields = decode_protobuf_wire(payload.data(), payload.size());
            std::string header = "gRPC frame: compressed=" + std::string(compressed ? "yes" : "no")
                               + " length=" + std::to_string(msg_len) + "\n";
            auto text = header + protobuf_to_text(fields);
            return { true, std::vector<uint8_t>(text.begin(), text.end()), {} };
        }
    });


    register_transform({
        "to_upper", "To Uppercase", "String", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            std::vector<uint8_t> out(input.size());
            std::transform(input.begin(), input.end(), out.begin(),
                [](uint8_t c) -> uint8_t { return (c >= 'a' && c <= 'z') ? c - 32 : c; });
            return { true, std::move(out), {} };
        }
    });

    register_transform({
        "to_lower", "To Lowercase", "String", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            std::vector<uint8_t> out(input.size());
            std::transform(input.begin(), input.end(), out.begin(),
                [](uint8_t c) -> uint8_t { return (c >= 'A' && c <= 'Z') ? c + 32 : c; });
            return { true, std::move(out), {} };
        }
    });

    register_transform({
        "reverse", "Reverse", "String", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            std::vector<uint8_t> out(input.rbegin(), input.rend());
            return { true, std::move(out), {} };
        }
    });

    register_transform({
        "count_bytes", "Byte Count", "Analysis", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            std::string s = std::to_string(input.size()) + " bytes";
            return { true, std::vector<uint8_t>(s.begin(), s.end()), {} };
        }
    });

    register_transform({
        "entropy", "Calculate Entropy", "Analysis", {},
        [](const std::vector<uint8_t>& input, const std::map<std::string, std::string>&) -> transform_result {
            if (input.empty()) return { true, {}, {} };
            int freq[256] = {};
            for (auto b : input) freq[b]++;
            double entropy = 0.0;
            double sz = static_cast<double>(input.size());
            for (int i = 0; i < 256; ++i) {
                if (freq[i] == 0) continue;
                double p = static_cast<double>(freq[i]) / sz;
                entropy -= p * log2(p);
            }
            std::string s = "Entropy: " + std::to_string(entropy) + " bits/byte (max 8.0)\n";
            s += "Size: " + std::to_string(input.size()) + " bytes\n";
            if (entropy > 7.5) s += "Assessment: High entropy — likely encrypted or compressed\n";
            else if (entropy > 5.0) s += "Assessment: Medium entropy — possibly compressed or encoded\n";
            else s += "Assessment: Low entropy — likely plaintext or structured data\n";
            return { true, std::vector<uint8_t>(s.begin(), s.end()), {} };
        }
    });
}

}
