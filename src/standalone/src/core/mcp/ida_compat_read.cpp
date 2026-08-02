#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "ida_compat_read.hpp"

#include "../analysis/decompiler/decompiler_ui_integration.hpp"
#include "../analysis/workspace/analysis_workspace.hpp"
#include "../analysis/workspace/decompiler_service.hpp"
#include "../analysis/workspace/compact_ir.hpp"
#include "../analysis/workspace/overlay_journal.hpp"
#include "../analysis/workspace/search_index.hpp"
#include "../analysis/workspace/pe_image.hpp"
#include "../analysis/workspace/byte_provider.hpp"
#include "../analysis/workspace/arch_decoder.hpp"
#include "../analysis/workspace/calling_convention.hpp"
#include "../analysis/workspace/x86_decoder.hpp"
#include "../analysis/workspace/workspace_registry.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <limits>
#include <memory>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../infra/cancellation_watchdog.hpp"
#include "../../helpers/diag_log.hpp"

namespace mcp_standalone::ida_compat
{
    using json = nlohmann::json;
    using namespace aida::analysis;

    namespace
    {
        std::optional<std::uint64_t> parse_addr(const json& j)
        {
            if (j.is_number_unsigned()) return j.get<std::uint64_t>();
            if (j.is_number_integer()) {
                const auto value = j.get<std::int64_t>();
                if (value < 0) return std::nullopt;
                return static_cast<std::uint64_t>(value);
            }
            if (!j.is_string()) return std::nullopt;
            std::string s = j.get<std::string>();
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
            if (s.empty()) return std::nullopt;
            std::string lo; lo.reserve(s.size());
            for (char c : s) lo.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            try {
                if (lo.rfind("va:", 0) == 0) return static_cast<std::uint64_t>(std::stoull(s.substr(3), nullptr, 0));
                if (lo.rfind("rva:", 0) == 0) return static_cast<std::uint64_t>(std::stoull(s.substr(4), nullptr, 0));
                if (lo.rfind("file:", 0) == 0) return static_cast<std::uint64_t>(std::stoull(s.substr(5), nullptr, 0));
                if (lo.size() > 1 && lo[0] == '0' && lo[1] == 'x') return static_cast<std::uint64_t>(std::stoull(s.substr(2), nullptr, 16));
                if (!lo.empty() && lo.back() == 'h' && lo.size() > 1) return static_cast<std::uint64_t>(std::stoull(s.substr(0, s.size()-1), nullptr, 16));
                return static_cast<std::uint64_t>(std::stoull(s, nullptr, 0));
            }
            catch (...) { return std::nullopt; }
        }

        std::string hex_str(std::uint64_t v) {
            std::ostringstream oss; oss << "0x" << std::hex << std::uppercase << v; return oss.str();
        }

        std::vector<json> to_vec(const json& obj, const char* key) {
            std::vector<json> r;
            if (!obj.contains(key)) return r;
            const auto& v = obj[key];
            if (v.is_array()) { for (const auto& i : v) r.push_back(i); }
            else r.push_back(v);
            return r;
        }

        const char* prov_str(fact_provenance_t p) {
            switch (p) {
            case fact_provenance_t::gap_recovery: return "gap_recovery";
            case fact_provenance_t::linear_validation: return "linear_validation";
            case fact_provenance_t::recursive_decode: return "recursive_decode";
            case fact_provenance_t::relocation: return "relocation";
            case fact_provenance_t::call_target: return "call_target";
            case fact_provenance_t::export_entry: return "export_entry";
            case fact_provenance_t::tls_entry: return "tls_entry";
            case fact_provenance_t::image_entry: return "image_entry";
            case fact_provenance_t::unwind_metadata: return "unwind_metadata";
            case fact_provenance_t::debug_symbol: return "debug_symbol";
            case fact_provenance_t::user_definition: return "user_definition";
            case fact_provenance_t::decompiler_feedback: return "decompiler_feedback";
            default: return "unknown";
            }
        }

        const char* xref_k_str(xref_kind_t k) {
            switch (k) {
            case xref_kind_t::code: return "code"; case xref_kind_t::call: return "call";
            case xref_kind_t::read: return "read"; case xref_kind_t::write: return "write";
            case xref_kind_t::address: return "address"; case xref_kind_t::relocation: return "relocation";
            default: return "unknown";
            }
        }

        const char* edge_k_str(edge_kind_t k) {
            switch (k) {
            case edge_kind_t::fallthrough: return "fallthrough";
            case edge_kind_t::conditional_taken: return "conditional_taken";
            case edge_kind_t::unconditional: return "unconditional";
            case edge_kind_t::call: return "call"; case edge_kind_t::tail_call: return "tail_call";
            case edge_kind_t::return_edge: return "return"; case edge_kind_t::exception_edge: return "exception";
            case edge_kind_t::indirect: return "indirect"; default: return "unknown";
            }
        }

        const char* sym_k_str(symbol_kind_t k) {
            switch (k) {
            case symbol_kind_t::function: return "function"; case symbol_kind_t::data: return "data";
            case symbol_kind_t::import_symbol: return "import"; case symbol_kind_t::export_symbol: return "export";
            case symbol_kind_t::debug_symbol: return "debug"; case symbol_kind_t::type_symbol: return "type";
            case symbol_kind_t::metadata: return "metadata"; default: return "unknown";
            }
        }

        const char* str_enc_str(string_encoding_t e) {
            switch (e) {
            case string_encoding_t::ascii: return "ascii"; case string_encoding_t::utf8: return "utf8";
            case string_encoding_t::utf16_le: return "utf16_le"; default: return "unknown";
            }
        }

        std::string bytes_to_hex(const std::uint8_t* d, std::size_t n) {
            static const char h[] = "0123456789ABCDEF"; std::string r; r.reserve(n*3);
            for (std::size_t i = 0; i < n; ++i) { if (i>0) r.push_back(' '); r.push_back(h[(d[i]>>4)&0xF]); r.push_back(h[d[i]&0xF]); }
            return r;
        }

        std::string json_safe_utf8(std::string_view input) {
            std::string output;
            output.reserve(input.size());
            for (std::size_t i = 0; i < input.size();) {
                const auto lead = static_cast<unsigned char>(input[i]);
                if (lead < 0x80) { output.push_back(static_cast<char>(lead)); ++i; continue; }
                std::size_t width = 0;
                std::uint32_t code_point = 0;
                if (lead >= 0xC2 && lead <= 0xDF) { width = 2; code_point = lead & 0x1F; }
                else if (lead >= 0xE0 && lead <= 0xEF) { width = 3; code_point = lead & 0x0F; }
                else if (lead >= 0xF0 && lead <= 0xF4) { width = 4; code_point = lead & 0x07; }
                if (width == 0 || i + width > input.size()) { output += "\xEF\xBF\xBD"; ++i; continue; }
                bool valid = true;
                for (std::size_t j = 1; j < width; ++j) {
                    const auto byte = static_cast<unsigned char>(input[i + j]);
                    if ((byte & 0xC0) != 0x80) { valid = false; break; }
                    code_point = (code_point << 6) | (byte & 0x3F);
                }
                if ((width == 3 && code_point < 0x800) || (width == 4 && code_point < 0x10000) ||
                    (code_point >= 0xD800 && code_point <= 0xDFFF) || code_point > 0x10FFFF) valid = false;
                if (!valid) { output += "\xEF\xBF\xBD"; ++i; continue; }
                output.append(input.data() + i, width);
                i += width;
            }
            return output;
        }

        std::optional<std::vector<std::uint8_t>> parse_hex_bytes(std::string_view input) {
            std::string hex;
            hex.reserve(input.size());
            for (char c : input) {
                if (std::isspace(static_cast<unsigned char>(c)) || c == ':' || c == '-') continue;
                if (!std::isxdigit(static_cast<unsigned char>(c))) return std::nullopt;
                hex.push_back(c);
            }
            if (hex.empty() || (hex.size() & 1U) != 0) return std::nullopt;
            std::vector<std::uint8_t> bytes;
            bytes.reserve(hex.size() / 2);
            const auto value = [](char c) -> std::uint8_t {
                if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                return static_cast<std::uint8_t>(c - 'a' + 10);
            };
            for (std::size_t i = 0; i < hex.size(); i += 2)
                bytes.push_back(static_cast<std::uint8_t>((value(hex[i]) << 4) | value(hex[i + 1])));
            return bytes;
        }

        std::vector<std::uint8_t> read_provider_bytes(const byte_provider_t& p, std::uint64_t off, std::size_t sz) {
            auto r = p.read_vector(off, sz, 16ULL*1024ULL*1024ULL);
            if (r.has_value()) return std::move(r.take_value());
            return {};
        }

        const function_record_t* find_func_at(const analysis_snapshot_t& s, std::uint64_t rva) {
            for (const auto& f : s.functions) if (f.start.value == rva) return &f; return nullptr;
        }

        const function_record_t* find_func_in(const analysis_snapshot_t& s, std::uint64_t rva) {
            for (const auto& f : s.functions) {
                if (rva >= f.start.value && rva < f.end.value) return &f;
                for (const auto& c : s.function_chunks_of(f)) if (rva >= c.rva_start && rva < c.rva_end) return &f;
            }
            return nullptr;
        }

        const symbol_record_t* find_sym_name(const analysis_snapshot_t& s, const std::string& n) {
            for (const auto& sy : s.symbols) if (sy.name == n) return &sy; return nullptr;
        }

        struct overlay_names_t {
            std::unordered_map<std::uint64_t,std::string> names, comments;
            explicit overlay_names_t(const overlay_journal_t* ov) {
                if (!ov) return;
                auto snap = ov->snapshot();
                for (const auto& [k, op] : snap.items) {
                    auto a = op.address.value;
                    if (op.kind == overlay_operation_kind_t::name) names[a] = op.name;
                    else if (op.kind == overlay_operation_kind_t::comment) comments[a] = op.text;
                }
            }
            const std::string* fn(std::uint64_t a) const { auto it = names.find(a); return it==names.end()?nullptr:&it->second; }
            const std::string* fc(std::uint64_t a) const { auto it = comments.find(a); return it==comments.end()?nullptr:&it->second; }
        };

        struct ws_state {
            std::shared_ptr<analysis_workspace_t> workspace;
            std::shared_ptr<const analysis_publication_t> publication;
            std::shared_ptr<const analysis_snapshot_t> snapshot;
            std::shared_ptr<search_index_t> search_index;
            std::shared_ptr<const pe_image_t> image;
            std::shared_ptr<const workspace_image_t> normalized_image;
            std::shared_ptr<overlay_journal_t> overlay;
            const byte_provider_t* provider = nullptr;
            target_kind_t kind = target_kind_t::static_file;
            overlay_names_t ov_names;
            explicit ws_state(const workspace_request_context_t& ctx) : ov_names(nullptr) {
                if (!ctx.workspace) return;
                workspace = ctx.workspace;
                publication = workspace->analysis_publication();
                if (publication) {
                    snapshot = publication->snapshot;
                    search_index = publication->search_index;
                }
                image = ctx.workspace->image(); normalized_image = ctx.workspace->normalized_image();
                overlay = ctx.workspace->overlay();
                provider = &ctx.workspace->provider();
                kind = ctx.kind;
                ov_names = overlay_names_t(overlay.get());
            }
            bool ok() const { return snapshot != nullptr; }
            bool has_image() const { return normalized_image != nullptr; }
            bool has_provider() const { return provider != nullptr; }
            bool live() const { return kind == target_kind_t::live_snapshot; }
        };

        constexpr std::uint64_t kMaxPageItems = 10000;
        constexpr std::uint64_t kMaxOutputBytes = 1024ULL * 1024ULL;
        constexpr std::uint64_t kMaxByteRead = 65536;
        constexpr std::uint64_t kMaxByteScan = 256ULL * 1024ULL * 1024ULL;
        constexpr std::uint64_t kMaxInstructionFormatScan = 100000;
        constexpr std::uint64_t kMaxInstructionFormatErrors = 256;

        json adapter_provenance(const workspace_request_context_t& ctx) {
            json meta = {
                {"adapter", "ida_compat_read"},
                {"analysis_revision", ctx.analysis_revision},
                {"overlay_revision", ctx.overlay_revision},
                {"target_kind", ctx.kind == target_kind_t::live_snapshot ? "live" : "static"}
            };
            if (ctx.pid.has_value()) meta["pid"] = *ctx.pid;
            else meta["pid"] = nullptr;
            if (!ctx.binary_id.empty()) meta["binary_id"] = ctx.binary_id.to_hex();
            return meta;
        }

        tool_result_t adapter_error(const workspace_request_context_t& ctx, std::string message,
                                    std::string code, json details = json::object()) {
            if (!details.is_object()) details = json::object();
            details["_meta"]["aida"] = adapter_provenance(ctx);
            return tool_result_t::error(message, code, details);
        }

        tool_result_t adapter_ok(const workspace_request_context_t& ctx, json data) {
            if (!data.is_object()) data = json{{"result", std::move(data)}};
            data["_meta"]["aida"] = adapter_provenance(ctx);
            if (data.dump().size() > kMaxOutputBytes)
                return adapter_error(ctx, "result exceeds the adapter output limit", "OUTPUT_LIMIT",
                    json{{"max_output_bytes", kMaxOutputBytes}});
            return tool_result_t::ok(data);
        }

        std::optional<tool_result_t> stop_result(const workspace_request_context_t& ctx) {
            if (ctx.cancellation_requested())
                return adapter_error(ctx, "request cancelled", "CANCELLED",
                    json{{"disposition", "partial_result_discarded"}});
            if (ctx.deadline_ms != 0 && static_cast<std::uint64_t>(GetTickCount64()) >= ctx.deadline_ms)
                return adapter_error(ctx, "request deadline exceeded", "DEADLINE_EXCEEDED",
                    json{{"disposition", "partial_result_discarded"}});
            return std::nullopt;
        }

        tool_result_t live_unsupported(const workspace_request_context_t& ctx, const char* operation,
                                       const char* hook) {
            return adapter_error(ctx, std::string("live target is unsupported for ") + operation,
                "LIVE_TARGET_UNSUPPORTED", json{{"operation", operation}, {"missing_hook", hook}});
        }

        std::uint64_t bounded_param(const json& params, const char* key, std::uint64_t fallback,
                                     std::uint64_t maximum) {
            if (!params.contains(key)) return fallback;
            const auto& value = params[key];
            if (value.is_number_unsigned()) return std::min(value.get<std::uint64_t>(), maximum);
            if (value.is_number_integer()) {
                const auto signed_value = value.get<std::int64_t>();
                if (signed_value >= 0) return std::min(static_cast<std::uint64_t>(signed_value), maximum);
            }
            return fallback;
        }

        cancellation_source_t request_cancellation_source(const workspace_request_context_t& ctx) {
            cancellation_source_t source;
            if (ctx.deadline_ms != 0) {
                const auto now = static_cast<std::uint64_t>(GetTickCount64());
                source.set_deadline(std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(now < ctx.deadline_ms ? ctx.deadline_ms - now : 0));
            }
            return source;
        }

        class request_cancellation_bridge_t final {
        public:
            request_cancellation_bridge_t(
                const workspace_request_context_t& context,
                cancellation_source_t& source) {
                if (!context.cancellation) {
                    ready_ = true;
                    return;
                }
                aida::infra::cancellation_watchdog::watch_descriptor_t watch;
                watch.external_flag = context.cancellation;
                watch.on_fire = [source_snapshot = source]() mutable {
                    source_snapshot.request_cancel();
                };
                watch_id_ = aida::infra::cancellation_watchdog::register_watch(std::move(watch));
                ready_ = watch_id_.valid();
            }

            ~request_cancellation_bridge_t() {
                if (watch_id_.valid())
                    aida::infra::cancellation_watchdog::unregister_watch(watch_id_);
            }

            request_cancellation_bridge_t(
                const request_cancellation_bridge_t&) = delete;
            request_cancellation_bridge_t& operator=(
                const request_cancellation_bridge_t&) = delete;

            bool ready() const noexcept { return ready_; }

        private:
            aida::infra::cancellation_watchdog::watch_id_t watch_id_;
            bool ready_ = false;
        };

        json formatter_error_json(const workspace_error_t& error,
                                  const workspace_image_t& image,
                                  std::string_view backend) {
            json value = {
                {"code", error.stable_code()},
                {"message", error.message},
                {"phase", error.phase},
                {"backend", std::string(backend)},
                {"architecture", static_cast<unsigned>(image.architecture)},
                {"architecture_mode", static_cast<unsigned>(image.architecture_mode)}
            };
            if (error.offset) value["provider_offset"] = *error.offset;
            if (error.address) value["address"] = hex_str(error.address->value);
            if (error.size) value["size"] = *error.size;
            if (error.cancellation) value["cancellation"] = true;
            if (error.deadline) value["deadline"] = true;
            if (!error.details.empty()) {
                json details = json::object();
                for (const auto& [name, detail] : error.details) details[name] = detail;
                value["details"] = std::move(details);
            }
            return value;
        }

        std::string trim_copy(std::string value) {
            const auto first = value.find_first_not_of(" \t\r\n");
            if (first == std::string::npos) return {};
            const auto last = value.find_last_not_of(" \t\r\n");
            return value.substr(first, last - first + 1);
        }

        std::string lower_copy(std::string_view value) {
            std::string normalized;
            normalized.reserve(value.size());
            for (const auto ch : value)
                normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
            return normalized;
        }

        bool is_identifier_char(char value) {
            const auto byte = static_cast<unsigned char>(value);
            return std::isalnum(byte) != 0 || value == '_' || value == ':';
        }

        bool has_identifier(std::string_view value, std::string_view identifier) {
            if (identifier.empty()) return false;
            const auto normalized = lower_copy(value);
            const auto expected = lower_copy(identifier);
            for (std::size_t position = normalized.find(expected); position != std::string::npos;
                 position = normalized.find(expected, position + 1)) {
                const bool before = position == 0 || !is_identifier_char(normalized[position - 1]);
                const auto end = position + expected.size();
                const bool after = end == normalized.size() || !is_identifier_char(normalized[end]);
                if (before && after) return true;
            }
            return false;
        }

        std::string canonical_type_name(std::string_view value) {
            const auto normalized = lower_copy(value);
            std::string token;
            std::string last;
            const auto flush = [&]() {
                if (token.empty()) return;
                if (token != "const" && token != "volatile" && token != "struct" && token != "class" &&
                    token != "union" && token != "enum" && token != "signed" && token != "unsigned" &&
                    token != "long" && token != "short" && token != "static" && token != "mutable")
                    last = token;
                token.clear();
            };
            for (const auto ch : normalized) {
                if (is_identifier_char(ch)) token.push_back(ch);
                else flush();
            }
            flush();
            return last;
        }

        std::string strip_c_comments(std::string_view value) {
            std::string output;
            output.reserve(value.size());
            bool line_comment = false;
            bool block_comment = false;
            char quote = 0;
            for (std::size_t index = 0; index < value.size(); ++index) {
                const auto ch = value[index];
                const auto next = index + 1 < value.size() ? value[index + 1] : '\0';
                if (line_comment) {
                    if (ch == '\n') { line_comment = false; output.push_back(ch); }
                    continue;
                }
                if (block_comment) {
                    if (ch == '*' && next == '/') { block_comment = false; ++index; }
                    continue;
                }
                if (quote != 0) {
                    output.push_back(ch);
                    if (ch == '\\' && index + 1 < value.size()) output.push_back(value[++index]);
                    else if (ch == quote) quote = 0;
                    continue;
                }
                if (ch == '\'' || ch == '"') { quote = ch; output.push_back(ch); continue; }
                if (ch == '/' && next == '/') { line_comment = true; ++index; continue; }
                if (ch == '/' && next == '*') { block_comment = true; ++index; continue; }
                output.push_back(ch);
            }
            return output;
        }

        std::vector<std::string> split_top_level(std::string_view value, char delimiter) {
            std::vector<std::string> parts;
            std::size_t begin = 0;
            std::uint32_t parens = 0;
            std::uint32_t brackets = 0;
            std::uint32_t braces = 0;
            char quote = 0;
            for (std::size_t index = 0; index < value.size(); ++index) {
                const auto ch = value[index];
                if (quote != 0) {
                    if (ch == '\\') ++index;
                    else if (ch == quote) quote = 0;
                    continue;
                }
                if (ch == '\'' || ch == '"') { quote = ch; continue; }
                if (ch == '(') ++parens;
                else if (ch == ')' && parens != 0) --parens;
                else if (ch == '[') ++brackets;
                else if (ch == ']' && brackets != 0) --brackets;
                else if (ch == '{') ++braces;
                else if (ch == '}' && braces != 0) --braces;
                else if (ch == delimiter && parens == 0 && brackets == 0 && braces == 0) {
                    parts.push_back(trim_copy(std::string(value.substr(begin, index - begin))));
                    begin = index + 1;
                }
            }
            parts.push_back(trim_copy(std::string(value.substr(begin))));
            return parts;
        }

        struct declared_type_t {
            std::string name;
            std::string definition;
        };

        struct struct_field_layout_t {
            std::string name;
            std::string type;
            std::string nested_type;
            std::string error;
            std::uint64_t offset = 0;
            std::uint64_t size = 0;
            std::uint64_t alignment = 1;
            std::uint32_t array_count = 1;
            bool is_pointer = false;
            bool is_signed = false;
        };

        struct struct_layout_t {
            std::string name;
            std::string definition;
            std::string error;
            std::vector<struct_field_layout_t> fields;
            std::uint64_t size = 0;
            std::uint64_t alignment = 1;
            bool complete = true;
        };

        struct type_shape_t {
            std::string nested_type;
            std::string error;
            std::uint64_t size = 0;
            std::uint64_t alignment = 1;
            bool is_pointer = false;
            bool is_signed = false;
        };

        std::vector<declared_type_t> declared_types(const ws_state& ws) {
            std::vector<declared_type_t> result;
            if (!ws.overlay) return result;
            const auto snapshot = ws.overlay->snapshot();
            result.reserve(snapshot.items.size());
            for (const auto& item : snapshot.items) {
                const auto& operation = item.second;
                if (operation.kind != overlay_operation_kind_t::type_declaration || operation.name.empty()) continue;
                result.push_back({operation.name, operation.text});
            }
            std::sort(result.begin(), result.end(), [](const auto& lhs, const auto& rhs) {
                return std::tuple{lower_copy(lhs.name), lhs.name, lhs.definition} <
                    std::tuple{lower_copy(rhs.name), rhs.name, rhs.definition};
            });
            return result;
        }

        const declared_type_t* find_declared_type(const std::vector<declared_type_t>& types,
                                                   std::string_view name) {
            const auto canonical = canonical_type_name(name);
            for (const auto& type : types)
                if (std::string_view(type.name) == name || canonical_type_name(type.name) == canonical) return &type;
            return nullptr;
        }

        std::optional<std::uint64_t> parse_decimal(std::string_view value) {
            const auto trimmed = trim_copy(std::string(value));
            if (trimmed.empty()) return std::nullopt;
            for (const auto ch : trimmed)
                if (std::isdigit(static_cast<unsigned char>(ch)) == 0) return std::nullopt;
            try { return std::stoull(trimmed); }
            catch (...) { return std::nullopt; }
        }

        std::uint64_t align_value(std::uint64_t value, std::uint64_t alignment) {
            if (alignment <= 1) return value;
            const auto remainder = value % alignment;
            if (remainder == 0) return value;
            if (value > (std::numeric_limits<std::uint64_t>::max)() - (alignment - remainder))
                return (std::numeric_limits<std::uint64_t>::max)();
            return value + alignment - remainder;
        }

        std::uint64_t declaration_pack(std::string_view definition) {
            const auto normalized = lower_copy(definition);
            const auto pragma = normalized.find("#pragma pack");
            if (pragma == std::string::npos) return 8;
            const auto close = normalized.find(')', pragma);
            if (close == std::string::npos) return 8;
            const auto comma = normalized.rfind(',', close);
            const auto open = normalized.find('(', pragma);
            if (open == std::string::npos || (comma == std::string::npos && open >= close)) return 8;
            const auto value = parse_decimal(normalized.substr((comma == std::string::npos ? open : comma) + 1,
                close - (comma == std::string::npos ? open : comma) - 1));
            if (!value || (*value != 1 && *value != 2 && *value != 4 && *value != 8 && *value != 16)) return 8;
            return *value;
        }

        bool declaration_body(std::string_view definition, std::string& body) {
            const auto cleaned = strip_c_comments(definition);
            const auto open = cleaned.find('{');
            if (open == std::string::npos) return false;
            std::uint32_t depth = 0;
            for (std::size_t index = open; index < cleaned.size(); ++index) {
                if (cleaned[index] == '{') ++depth;
                else if (cleaned[index] == '}') {
                    if (depth == 0) return false;
                    if (--depth == 0) {
                        body = cleaned.substr(open + 1, index - open - 1);
                        return true;
                    }
                }
            }
            return false;
        }

        std::string normalize_field_type(std::string value) {
            value = trim_copy(std::move(value));
            const auto assignment = value.find('=');
            if (assignment != std::string::npos) value.resize(assignment);
            value = trim_copy(std::move(value));
            static const std::array<std::string_view, 5> removable = {
                "const ", "volatile ", "mutable ", "static ", "register "};
            bool changed = true;
            while (changed) {
                changed = false;
                const auto lower = lower_copy(value);
                for (const auto prefix : removable) {
                    if (lower.rfind(prefix, 0) == 0) {
                        value.erase(0, prefix.size());
                        value = trim_copy(std::move(value));
                        changed = true;
                        break;
                    }
                }
            }
            return value;
        }

        bool parse_field_declaration(std::string declaration, std::string inherited_type,
                                     std::string& name, std::string& type, std::uint32_t& array_count,
                                     std::string& error) {
            declaration = trim_copy(std::move(declaration));
            if (declaration.empty()) return false;
            std::size_t bitfield = std::string::npos;
            for (std::size_t index = 0; index < declaration.size(); ++index) {
                if (declaration[index] == ':' && (index == 0 || declaration[index - 1] != ':') &&
                    (index + 1 == declaration.size() || declaration[index + 1] != ':')) {
                    bitfield = index;
                    break;
                }
            }
            if (bitfield != std::string::npos) {
                error = "bitfield layout is unsupported";
                return true;
            }
            const auto function_pointer = declaration.find("(*");
            if (function_pointer != std::string::npos) {
                const auto name_begin = declaration.find_first_not_of(" \t", function_pointer + 2);
                if (name_begin == std::string::npos) { error = "function pointer declarator is malformed"; return true; }
                auto name_end = name_begin;
                while (name_end < declaration.size() &&
                       (std::isalnum(static_cast<unsigned char>(declaration[name_end])) != 0 || declaration[name_end] == '_')) ++name_end;
                if (name_end == name_begin) { error = "function pointer declarator is malformed"; return true; }
                name = declaration.substr(name_begin, name_end - name_begin);
                type = normalize_field_type(declaration.substr(0, function_pointer) + " *");
                return true;
            }
            array_count = 1;
            const auto open = declaration.rfind('[');
            if (open != std::string::npos) {
                const auto close = declaration.find(']', open);
                if (close == std::string::npos || !trim_copy(declaration.substr(close + 1)).empty()) {
                    error = "array declarator is malformed";
                    return true;
                }
                const auto count = parse_decimal(declaration.substr(open + 1, close - open - 1));
                if (!count || *count == 0 || *count > 65536) {
                    error = "array count is unsupported";
                    return true;
                }
                array_count = static_cast<std::uint32_t>(*count);
                declaration = trim_copy(declaration.substr(0, open));
            }
            auto name_end = declaration.size();
            while (name_end != 0 && std::isspace(static_cast<unsigned char>(declaration[name_end - 1])) != 0) --name_end;
            auto name_begin = name_end;
            while (name_begin != 0 &&
                   (std::isalnum(static_cast<unsigned char>(declaration[name_begin - 1])) != 0 || declaration[name_begin - 1] == '_')) --name_begin;
            if (name_begin == name_end) { error = "field declarator is malformed"; return true; }
            name = declaration.substr(name_begin, name_end - name_begin);
            type = normalize_field_type(declaration.substr(0, name_begin));
            if (!inherited_type.empty() && (type.empty() || type == "*" || type == "&"))
                type = normalize_field_type(inherited_type + " " + type);
            if (type.empty()) error = "field type is missing";
            return true;
        }

        type_shape_t resolve_type_shape(const std::string& type, const std::vector<declared_type_t>& declarations,
                                        std::uint64_t pointer_size, std::uint32_t depth,
                                        std::unordered_set<std::string>& active);

        struct_layout_t build_struct_layout(const declared_type_t& declaration,
                                            const std::vector<declared_type_t>& declarations,
                                            std::uint64_t pointer_size, std::uint32_t depth,
                                            std::unordered_set<std::string>& active) {
            struct_layout_t layout;
            layout.name = declaration.name;
            layout.definition = declaration.definition;
            const auto canonical = canonical_type_name(declaration.name);
            if (depth >= 16 || !active.insert(canonical).second) {
                layout.complete = false;
                layout.error = depth >= 16 ? "nested type depth limit exceeded" : "recursive type layout";
                return layout;
            }
            std::string body;
            if (!declaration_body(declaration.definition, body)) {
                layout.complete = false;
                layout.error = "type declaration does not contain a complete aggregate body";
                active.erase(canonical);
                return layout;
            }
            const auto pack = declaration_pack(declaration.definition);
            std::uint64_t offset = 0;
            std::uint64_t aggregate_alignment = 1;
            for (const auto& statement : split_top_level(body, ';')) {
                if (statement.empty()) continue;
                std::string inherited_type;
                bool first = true;
                for (auto declarator : split_top_level(statement, ',')) {
                    if (declarator.empty()) continue;
                    struct_field_layout_t field;
                    std::uint32_t array_count = 1;
                    if (!parse_field_declaration(std::move(declarator), inherited_type, field.name, field.type,
                                                 array_count, field.error)) continue;
                    if (first) {
                        inherited_type = field.type;
                        while (!inherited_type.empty() &&
                               (inherited_type.back() == '*' || inherited_type.back() == '&' ||
                                std::isspace(static_cast<unsigned char>(inherited_type.back())) != 0))
                            inherited_type.pop_back();
                        inherited_type = trim_copy(std::move(inherited_type));
                        first = false;
                    }
                    field.array_count = array_count;
                    if (field.error.empty()) {
                        const auto shape = resolve_type_shape(field.type, declarations, pointer_size, depth + 1, active);
                        field.size = shape.size;
                        field.alignment = std::min<std::uint64_t>(std::max<std::uint64_t>(shape.alignment, 1), pack);
                        field.is_pointer = shape.is_pointer;
                        field.is_signed = shape.is_signed;
                        field.nested_type = shape.nested_type;
                        field.error = shape.error;
                        if (field.error.empty() && (field.size == 0 ||
                            field.size > (std::numeric_limits<std::uint64_t>::max)() / array_count))
                            field.error = "field size is invalid";
                    }
                    if (!field.error.empty()) {
                        layout.complete = false;
                        if (layout.error.empty()) layout.error = field.error;
                        layout.fields.push_back(std::move(field));
                        continue;
                    }
                    if (!layout.complete) {
                        field.error = "field offset is unavailable after an unresolved declaration";
                        if (layout.error.empty()) layout.error = field.error;
                        layout.fields.push_back(std::move(field));
                        continue;
                    }
                    field.size *= array_count;
                    offset = align_value(offset, field.alignment);
                    if (offset == (std::numeric_limits<std::uint64_t>::max)() ||
                        field.size > (std::numeric_limits<std::uint64_t>::max)() - offset) {
                        field.error = "field offset exceeds supported range";
                        layout.complete = false;
                        if (layout.error.empty()) layout.error = field.error;
                        layout.fields.push_back(std::move(field));
                        continue;
                    }
                    field.offset = offset;
                    offset += field.size;
                    aggregate_alignment = std::max(aggregate_alignment, field.alignment);
                    layout.fields.push_back(std::move(field));
                }
            }
            layout.alignment = std::min<std::uint64_t>(aggregate_alignment, pack);
            layout.size = align_value(offset, layout.alignment);
            if (layout.size == (std::numeric_limits<std::uint64_t>::max)()) {
                layout.size = 0;
                layout.complete = false;
                layout.error = "aggregate size exceeds supported range";
            }
            active.erase(canonical);
            return layout;
        }

        type_shape_t resolve_type_shape(const std::string& type, const std::vector<declared_type_t>& declarations,
                                        std::uint64_t pointer_size, std::uint32_t depth,
                                        std::unordered_set<std::string>& active) {
            type_shape_t shape;
            const auto normalized = lower_copy(normalize_field_type(type));
            if (normalized.find('*') != std::string::npos || normalized.find('&') != std::string::npos) {
                shape.size = pointer_size;
                shape.alignment = pointer_size;
                shape.is_pointer = true;
                return shape;
            }
            const auto scalar = [&](std::uint64_t size, bool signed_value) {
                shape.size = size;
                shape.alignment = std::min<std::uint64_t>(size, 8);
                shape.is_signed = signed_value;
            };
            if (normalized == "bool" || normalized == "char" || normalized == "signed char" || normalized == "unsigned char" ||
                normalized == "int8_t" || normalized == "uint8_t" || normalized == "byte" ||
                normalized == "std::byte") scalar(1, normalized.find("unsigned") == std::string::npos && normalized != "uint8_t");
            else if (normalized == "wchar_t" || normalized == "char16_t" || normalized == "short" ||
                     normalized == "short int" || normalized == "unsigned short" || normalized == "unsigned short int" ||
                     normalized == "int16_t" || normalized == "uint16_t") scalar(2, normalized.find("unsigned") == std::string::npos && normalized != "uint16_t");
            else if (normalized == "float" || normalized == "int" || normalized == "signed" || normalized == "signed int" ||
                     normalized == "unsigned" || normalized == "unsigned int" || normalized == "long" ||
                     normalized == "long int" || normalized == "unsigned long" || normalized == "unsigned long int" ||
                     normalized == "int32_t" || normalized == "uint32_t" || normalized == "char32_t") scalar(4, normalized.find("unsigned") == std::string::npos && normalized != "uint32_t" && normalized != "char32_t");
            else if (normalized == "double" || normalized == "long double" || normalized == "long long" ||
                     normalized == "long long int" || normalized == "unsigned long long" ||
                     normalized == "unsigned long long int" || normalized == "int64_t" || normalized == "uint64_t") scalar(8, normalized.find("unsigned") == std::string::npos && normalized != "uint64_t");
            else if (normalized == "size_t" || normalized == "intptr_t" || normalized == "uintptr_t") scalar(pointer_size, normalized != "uintptr_t");
            else if (normalized.rfind("enum ", 0) == 0) scalar(4, true);
            else {
                const auto name = canonical_type_name(normalized);
                const auto* declaration = find_declared_type(declarations, name);
                if (!declaration) {
                    shape.error = "field type is not a declared aggregate or supported scalar";
                    return shape;
                }
                auto nested = build_struct_layout(*declaration, declarations, pointer_size, depth, active);
                if (!nested.complete || nested.size == 0) {
                    shape.error = nested.error.empty() ? "nested aggregate layout is incomplete" : nested.error;
                    return shape;
                }
                shape.size = nested.size;
                shape.alignment = nested.alignment;
                shape.nested_type = declaration->name;
            }
            return shape;
        }

        std::uint64_t scalar_from_bytes(const std::uint8_t* bytes, std::uint64_t size, endian_t endian) {
            std::uint64_t value = 0;
            const auto bounded_size = std::min<std::uint64_t>(size, sizeof(value));
            if (endian == endian_t::big) {
                for (std::uint64_t index = 0; index < bounded_size; ++index) value = (value << 8U) | bytes[index];
            } else {
                for (std::uint64_t index = 0; index < bounded_size; ++index)
                    value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
            }
            return value;
        }

        std::uint64_t pointer_width_bytes(const workspace_image_t& image) {
            const auto bits = image.address_width_bits == 0 ? 64U : image.address_width_bits;
            return std::min<std::uint64_t>(8, std::max<std::uint64_t>(1, (bits + 7U) / 8U));
        }

        struct_layout_t resolve_struct_layout(std::string_view name, const std::vector<declared_type_t>& declarations,
                                              std::uint64_t pointer_size) {
            struct_layout_t layout;
            const auto* declaration = find_declared_type(declarations, name);
            if (!declaration) {
                layout.name = std::string(name);
                layout.complete = false;
                layout.error = "declared type was not found";
                return layout;
            }
            std::unordered_set<std::string> active;
            return build_struct_layout(*declaration, declarations, pointer_size, 0, active);
        }

        bool type_application_matches(std::string_view application, std::string_view declaration_name) {
            if (application.find('*') != std::string::npos || application.find('&') != std::string::npos) return false;
            const auto canonical = canonical_type_name(declaration_name);
            return has_identifier(application, declaration_name) || has_identifier(application, canonical);
        }

        bool append_struct_fields(json& output, const struct_layout_t& layout, const std::uint8_t* bytes,
                                  std::uint64_t available, const std::vector<declared_type_t>& declarations,
                                  std::uint64_t pointer_size, endian_t endian, std::uint64_t remaining_depth,
                                  const workspace_request_context_t& ctx) {
            for (const auto& field : layout.fields) {
                if (stop_result(ctx).has_value()) return false;
                json item = {{"name", field.name}, {"type", field.type}, {"offset", field.offset},
                    {"size", field.size}, {"array_count", field.array_count}, {"pointer", field.is_pointer}};
                if (!field.error.empty()) {
                    item["error"] = {{"code", "LAYOUT_UNRESOLVED"}, {"message", field.error}};
                    output.push_back(std::move(item));
                    continue;
                }
                if (field.offset > available || field.size > available - field.offset) {
                    item["error"] = {{"code", "READ_TRUNCATED"}, {"message", "field extends beyond available bytes"}};
                    output.push_back(std::move(item));
                    continue;
                }
                const auto* field_bytes = bytes + field.offset;
                item["raw"] = bytes_to_hex(field_bytes, static_cast<std::size_t>(field.size));
                if (field.array_count == 1 && field.size <= sizeof(std::uint64_t)) {
                    const auto value = scalar_from_bytes(field_bytes, field.size, endian);
                    if (field.is_pointer) item["value"] = hex_str(value);
                    else {
                        item["value"] = value;
                        if (field.is_signed && field.size != 0) {
                            const auto bits = field.size * 8;
                            const auto mask = bits < 64 ? ((1ULL << bits) - 1ULL) : ~0ULL;
                            item["signed_value"] = static_cast<std::int64_t>((value & (1ULL << (bits - 1))) != 0
                                ? value | ~mask : value);
                        }
                    }
                }
                if (!field.nested_type.empty() && field.array_count == 1) {
                    if (remaining_depth == 0) {
                        item["nested_truncated"] = true;
                    } else {
                        const auto nested = resolve_struct_layout(field.nested_type, declarations, pointer_size);
                        if (!nested.complete || nested.size == 0 || nested.size > field.size) {
                            item["nested_error"] = {{"code", "LAYOUT_UNRESOLVED"},
                                {"message", nested.error.empty() ? "nested layout is incomplete" : nested.error}};
                        } else {
                            json children = json::array();
                            if (!append_struct_fields(children, nested, field_bytes, field.size, declarations,
                                                      pointer_size, endian, remaining_depth - 1, ctx)) return false;
                            item["fields"] = std::move(children);
                        }
                    }
                }
                output.push_back(std::move(item));
            }
            return true;
        }

        const char* stack_slot_kind_string(stack_slot_kind_t kind) {
            switch (kind) {
            case stack_slot_kind_t::argument: return "argument";
            case stack_slot_kind_t::local: return "local";
            case stack_slot_kind_t::spill: return "spill";
            case stack_slot_kind_t::saved_register: return "saved_register";
            case stack_slot_kind_t::outgoing_argument: return "outgoing_argument";
            default: return "unknown";
            }
        }

        const char* calling_convention_state_string(cc_inference_state_t state) {
            switch (state) {
            case cc_inference_state_t::abstained: return "abstained";
            case cc_inference_state_t::inferred: return "inferred";
            case cc_inference_state_t::conflicted: return "conflicted";
            default: return "unknown";
            }
        }

        struct resolved_address_t {
            address_t address;
            std::optional<std::uint64_t> provider_offset;
        };

        bool span_contains(std::uint64_t start, std::uint64_t size, std::uint64_t value,
                           std::uint64_t requested_size = 1) {
            if (value < start) return false;
            const std::uint64_t delta = value - start;
            return delta <= size && requested_size <= size - delta;
        }

        std::optional<std::uint64_t> provider_offset_for(const workspace_image_t& image,
                                                          const address_t& address,
                                                          std::uint64_t requested_size = 1) {
            if (address.space == address_space_id_t::file_offset &&
                span_contains(0, image.provider_size, address.value, requested_size))
                return address.value;
            const auto translate = [&](address_space_id_t source_space, std::uint64_t source_value)
                -> std::optional<std::uint64_t> {
                for (const auto& mapping : image.address_mappings) {
                    if (mapping.source_space != source_space ||
                        !span_contains(mapping.source_start, mapping.size, source_value, requested_size))
                        continue;
                    const std::uint64_t mapped = mapping.target_start + (source_value - mapping.source_start);
                    if (mapping.target_space == address_space_id_t::file_offset) return mapped;
                    for (const auto& next : image.address_mappings) {
                        if (next.source_space == mapping.target_space &&
                            span_contains(next.source_start, next.size, mapped, requested_size) &&
                            next.target_space == address_space_id_t::file_offset)
                            return next.target_start + (mapped - next.source_start);
                    }
                }
                return std::nullopt;
            };
            if (auto mapped = translate(address.space, address.value)) return mapped;
            std::uint64_t rva = 0;
            if (address.space == address_space_id_t::relative_virtual) rva = address.value;
            else if (address.space == address_space_id_t::virtual_address && address.value >= image.image_base)
                rva = address.value - image.image_base;
            else return std::nullopt;
            const auto from_ranges = [&](const auto& ranges) -> std::optional<std::uint64_t> {
                for (const auto& range : ranges) {
                    if (span_contains(range.virtual_address, range.file_size, rva, requested_size))
                        return range.file_offset + (rva - range.virtual_address);
                }
                return std::nullopt;
            };
            if (auto offset = from_ranges(image.segments)) return offset;
            return from_ranges(image.sections);
        }

        std::optional<resolved_address_t> resolve_address(const ws_state& ws, const json& input) {
            auto value = parse_addr(input);
            if (!value || !ws.normalized_image) return std::nullopt;
            address_t address;
            address.architecture = ws.normalized_image->architecture;
            address.mode = ws.normalized_image->architecture_mode;
            std::string prefix;
            if (input.is_string()) {
                prefix = input.get<std::string>();
                const auto separator = prefix.find(':');
                if (separator != std::string::npos) {
                    prefix.resize(separator);
                    std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                } else prefix.clear();
            }
            if (prefix == "file") address.space = address_space_id_t::file_offset;
            else if (prefix == "rva") address.space = address_space_id_t::relative_virtual;
            else if (prefix == "va") address.space = ws.live() ? address_space_id_t::live_virtual : address_space_id_t::virtual_address;
            else if (ws.live()) address.space = address_space_id_t::live_virtual;
            else if (ws.normalized_image->image_base != 0 && *value >= ws.normalized_image->image_base &&
                     *value - ws.normalized_image->image_base < ws.normalized_image->image_size)
                address.space = address_space_id_t::virtual_address;
            else address.space = address_space_id_t::relative_virtual;
            address.value = *value;
            return resolved_address_t{address, provider_offset_for(*ws.normalized_image, address)};
        }

        std::optional<std::uint32_t> managed_token_value(std::string_view text) {
            if (text.empty()) return std::nullopt;
            const auto parsed = parse_addr(json(std::string(text)));
            if (!parsed || *parsed > (std::numeric_limits<std::uint32_t>::max)())
                return std::nullopt;
            return static_cast<std::uint32_t>(*parsed);
        }

        std::string func_name(const analysis_snapshot_t& s, const overlay_names_t& ov, const function_record_t& f) {
            if (auto* n = ov.fn(f.start.value)) return *n;
            if (f.symbol_id.has_value()) for (const auto& sy : s.symbols) if (sy.id == f.symbol_id.value()) return sy.name;
            return "sub_" + hex_str(f.start.value);
        }

        std::optional<decompiler_entity_locator_t> decompiler_locator(
            const ws_state& ws, const json& input) {
            if (input.is_string()) {
                std::string text = input.get<std::string>();
                while (!text.empty() && std::isspace(
                           static_cast<unsigned char>(text.front())))
                    text.erase(text.begin());
                while (!text.empty() && std::isspace(
                           static_cast<unsigned char>(text.back())))
                    text.pop_back();
                const auto separator = text.find(':');
                if (separator != std::string::npos) {
                    std::string prefix = text.substr(0, separator);
                    std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                        [](unsigned char value) {
                            return static_cast<char>(std::tolower(value));
                        });
                    const bool token_locator = prefix == "token" ||
                        prefix == "cli" || prefix == "jvm" ||
                        prefix == "dalvik";
                    if (token_locator) {
                        std::string value = text.substr(separator + 1);
                        std::optional<std::uint32_t> artifact;
                        const auto artifact_separator = value.find('@');
                        if (artifact_separator != std::string::npos) {
                            artifact = managed_token_value(
                                value.substr(artifact_separator + 1));
                            value.resize(artifact_separator);
                            if (!artifact) return std::nullopt;
                        }
                        const auto token = managed_token_value(value);
                        if (!token) return std::nullopt;
                        decompiler_entity_locator_t locator;
                        locator.token = *token;
                        locator.artifact_ordinal = artifact;
                        if (prefix == "cli")
                            locator.expected_kind =
                                decompiler_entity_kind_t::cli_method;
                        else if (prefix == "jvm")
                            locator.expected_kind =
                                decompiler_entity_kind_t::jvm_method;
                        else if (prefix == "dalvik")
                            locator.expected_kind =
                                decompiler_entity_kind_t::dalvik_method;
                        return locator;
                    }
                }
            }
            if (const auto resolved = resolve_address(ws, input)) {
                decompiler_entity_locator_t locator;
                locator.address = resolved->address.space ==
                        address_space_id_t::file_offset &&
                        resolved->provider_offset
                    ? *resolved->provider_offset
                    : resolved->address.value;
                return locator;
            }
            if (!input.is_string() || !ws.snapshot)
                return std::nullopt;
            const auto requested = input.get<std::string>();
            const function_record_t* match = nullptr;
            for (const auto& function : ws.snapshot->functions) {
                if (func_name(*ws.snapshot, ws.ov_names, function) != requested)
                    continue;
                if (match) return std::nullopt;
                match = &function;
            }
            if (!match) return std::nullopt;
            decompiler_entity_locator_t locator;
            locator.address = match->start.value;
            locator.expected_kind = decompiler_entity_kind_t::native_function;
            return locator;
        }

        std::string decompiler_entity_name(const decompiler_entity_key_t& entity) {
            if (const auto* native = std::get_if<
                    native_decompiler_entity_identity_t>(&entity.identity))
                return native->canonical_symbol;
            if (const auto* cli = std::get_if<
                    cli_decompiler_entity_identity_t>(&entity.identity))
                return cli->declaring_type + "::" + cli->method_name;
            if (const auto* jvm = std::get_if<
                    jvm_decompiler_entity_identity_t>(&entity.identity))
                return jvm->class_internal_name + "." + jvm->method_name;
            if (const auto* dalvik = std::get_if<
                    dalvik_decompiler_entity_identity_t>(&entity.identity))
                return dalvik->class_descriptor + "->" + dalvik->method_name;
            return {};
        }

        std::optional<std::string> decompiler_entity_prototype(
            const decompiler_entity_key_t& entity) {
            if (const auto* cli = std::get_if<
                    cli_decompiler_entity_identity_t>(&entity.identity))
                return cli->method_signature.empty()
                    ? std::nullopt
                    : std::optional<std::string>(cli->method_signature);
            if (const auto* jvm = std::get_if<
                    jvm_decompiler_entity_identity_t>(&entity.identity))
                return jvm->method_descriptor.empty()
                    ? std::nullopt
                    : std::optional<std::string>(jvm->method_descriptor);
            if (const auto* dalvik = std::get_if<
                    dalvik_decompiler_entity_identity_t>(&entity.identity))
                return dalvik->prototype.empty()
                    ? std::nullopt
                    : std::optional<std::string>(dalvik->prototype);
            return std::nullopt;
        }

        std::optional<std::string> decompiler_entity_locator_text(
            const ws_state& ws,
            const generation_bound_decompiler_entity_t& binding) {
            if (const auto* native = std::get_if<
                    native_decompiler_entity_identity_t>(&binding.entity.identity))
                return hex_str(native->entry.value);
            if (!binding.artifact_index || !ws.publication ||
                !ws.publication->managed_artifacts ||
                *binding.artifact_index >=
                    ws.publication->managed_artifacts->artifacts().size())
                return std::nullopt;
            const auto artifact = ws.publication->managed_artifacts->artifacts()
                [*binding.artifact_index].artifact_ordinal;
            std::string prefix;
            std::uint32_t token = 0;
            if (const auto* cli = std::get_if<
                    cli_decompiler_entity_identity_t>(&binding.entity.identity)) {
                prefix = "cli";
                token = cli->metadata_token;
            } else if (const auto* jvm = std::get_if<
                           jvm_decompiler_entity_identity_t>(&binding.entity.identity)) {
                prefix = "jvm";
                token = jvm->method_index;
            } else if (const auto* dalvik = std::get_if<
                           dalvik_decompiler_entity_identity_t>(&binding.entity.identity)) {
                prefix = "dalvik";
                token = dalvik->method_id;
            } else {
                return std::nullopt;
            }
            return prefix + ":" + std::to_string(token) + "@" +
                std::to_string(artifact);
        }

        std::uint64_t decompiler_entity_size(
            const ws_state& ws,
            const generation_bound_decompiler_entity_t& binding) noexcept {
            if (const auto* native = std::get_if<
                    native_decompiler_entity_identity_t>(&binding.entity.identity))
                return native->end.value >= native->entry.value
                    ? native->end.value - native->entry.value : 0;
            if (!binding.method_index || !ws.publication ||
                !ws.publication->managed_artifacts)
                return 0;
            for (const auto& method :
                 ws.publication->managed_artifacts->methods())
                if (method.method_index == *binding.method_index &&
                    method.entity == binding.entity)
                    return method.code_size;
            return 0;
        }

        json decompiler_source_mappings(
            const decompiler_ui_result_t& result,
            std::size_t maximum_bytes,
            bool& truncated) {
            truncated = false;
            json mappings = json::array();
            std::size_t serialized_bytes = 2;
            for (const auto& mapping : result.source_mappings) {
                if (mapping.token_begin >= mapping.token_end ||
                    mapping.token_end > result.rendered_text.size())
                    continue;
                json item{{"begin", mapping.token_begin},
                          {"end", mapping.token_end}};
                auto address_range = mapping.address_range;
                if (!address_range && mapping.coordinate)
                    address_range = mapping.coordinate->address_range;
                if (address_range) {
                    item["address"] = hex_str(address_range->begin.value);
                    item["address_begin"] = hex_str(
                        address_range->begin.value);
                    item["address_end"] = hex_str(
                        address_range->end.value);
                }
                const auto item_bytes = item.dump().size() + 1U;
                if (item_bytes > maximum_bytes -
                        (std::min)(maximum_bytes, serialized_bytes)) {
                    truncated = true;
                    break;
                }
                serialized_bytes += item_bytes;
                mappings.push_back(std::move(item));
                if (mappings.size() >= kMaxPageItems) {
                    truncated = result.source_mappings.size() > mappings.size();
                    break;
                }
            }
            return mappings;
        }

        std::optional<std::uint64_t> snapshot_address_value(const ws_state& ws,
                                                            const resolved_address_t& address) {
            if (!ws.normalized_image) return std::nullopt;
            if (ws.live()) return address.address.value;
            if (address.address.space == address_space_id_t::relative_virtual) return address.address.value;
            if (address.address.space == address_space_id_t::virtual_address &&
                address.address.value >= ws.normalized_image->image_base)
                return address.address.value - ws.normalized_image->image_base;
            if (address.address.space != address_space_id_t::file_offset) return std::nullopt;
            const auto from_ranges = [&](const auto& ranges) -> std::optional<std::uint64_t> {
                for (const auto& range : ranges) {
                    if (span_contains(range.file_offset, range.file_size, address.address.value))
                        return range.virtual_address + (address.address.value - range.file_offset);
                }
                return std::nullopt;
            };
            if (auto rva = from_ranges(ws.normalized_image->segments)) return rva;
            return from_ranges(ws.normalized_image->sections);
        }

        std::optional<std::uint64_t> snapshot_address_value(const ws_state& ws, const address_t& address) {
            return snapshot_address_value(ws, resolved_address_t{
                address, ws.normalized_image ? provider_offset_for(*ws.normalized_image, address) : std::nullopt});
        }

        std::optional<address_t> address_for_provider_offset(const workspace_image_t& image,
                                                             std::uint64_t provider_offset) {
            for (const auto& mapping : image.address_mappings) {
                if (mapping.source_space != address_space_id_t::file_offset ||
                    !span_contains(mapping.source_start, mapping.size, provider_offset))
                    continue;
                address_t address;
                address.space = mapping.target_space;
                address.value = mapping.target_start + (provider_offset - mapping.source_start);
                address.architecture = image.architecture;
                address.mode = image.architecture_mode;
                return address;
            }
            const auto from_ranges = [&](const auto& ranges) -> std::optional<address_t> {
                for (const auto& range : ranges) {
                    if (!span_contains(range.file_offset, range.file_size, provider_offset)) continue;
                    address_t address;
                    address.space = address_space_id_t::relative_virtual;
                    address.value = range.virtual_address + (provider_offset - range.file_offset);
                    address.architecture = image.architecture;
                    address.mode = image.architecture_mode;
                    return address;
                }
                return std::nullopt;
            };
            if (auto address = from_ranges(image.segments)) return address;
            return from_ranges(image.sections);
        }

        json func_json(const analysis_snapshot_t& s, const overlay_names_t& ov, const function_record_t& f) {
            json j; j["address"] = hex_str(f.start.value); j["end"] = hex_str(f.end.value);
            j["name"] = func_name(s, ov, f); j["size"] = f.end.value - f.start.value;
            j["blocks"] = f.block_count; j["chunks"] = f.chunk_count;
            j["thunk"] = f.thunk; j["noreturn"] = f.noreturn; j["provenance"] = prov_str(f.provenance);
            const auto f_ranges = s.function_chunks_of(f); if (f_ranges.size() > 1) { json ch = json::array(); for (const auto& c : f_ranges) ch.push_back({{"start",hex_str(c.rva_start)},{"end",hex_str(c.rva_end)}}); j["chunk_ranges"] = ch; }
            return j;
        }

        json sym_json(const symbol_record_t& s) {
            return {{"address",hex_str(s.address.value)},{"name",s.name},{"kind",sym_k_str(s.kind)},{"provenance",prov_str(s.provenance)}};
        }

        json xref_json(const xref_record_t& x) {
            return {{"from",hex_str(x.source.value)},{"to",hex_str(x.target.value)},{"kind",xref_k_str(x.kind)},{"provenance",prov_str(x.provenance)}};
        }

        json block_json(const basic_block_record_t& b) {
            return {{"start",hex_str(b.start.value)},{"end",hex_str(b.end.value)},{"instructions",b.instruction_count},{"provenance",prov_str(b.provenance)}};
        }

        json str_json(const string_record_t& s) {
            return {{"address",hex_str(s.address.value)},{"encoding",str_enc_str(s.encoding)},{"length",s.byte_length},{"value",s.value}};
        }

        std::uint64_t parse_int_val(const std::string& s, const std::string& fmt) {
            if (fmt == "hex") { std::string c = (s.size()>2&&s[0]=='0'&&(s[1]=='x'||s[1]=='X'))?s.substr(2):s; return std::stoull(c, nullptr, 16); }
            if (fmt == "octal") return std::stoull(s, nullptr, 8);
            if (fmt == "binary") { std::string c = (s.size()>2&&s[0]=='0'&&s[1]=='b')?s.substr(2):s; return std::stoull(c, nullptr, 2); }
            if (fmt == "ascii") { std::uint64_t v = 0; for (char c : s) v = (v<<8)|static_cast<unsigned char>(c); return v; }
            return std::stoull(s, nullptr, 0);
        }

        std::string fmt_int(std::uint64_t v, const std::string& fmt) {
            if (fmt == "hex") { std::ostringstream o; o << "0x" << std::hex << std::uppercase << v; return o.str(); }
            if (fmt == "octal") { std::ostringstream o; o << "0o" << std::oct << v; return o.str(); }
            if (fmt == "binary") { std::string b; for (int i = 63; i >= 0; --i) b.push_back((v>>i)&1?'1':'0'); auto p = b.find_first_of('1'); if (p == std::string::npos) return "0b0"; return "0b" + b.substr(p); }
            if (fmt == "ascii") { std::string r; for (int i = 7; i >= 0; --i) { unsigned char c = static_cast<unsigned char>((v >> (i*8)) & 0xFF); if (c) r.push_back(c); } return r; }
            return std::to_string(v);
        }
    }

    tool_result_t tool_lookup_funcs(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.ok() || !ws.normalized_image) return adapter_error(ctx, "no analysis snapshot available", "NO_SNAPSHOT");
        auto names = to_vec(params, "names");
        if (params.contains("name") && !params["name"].is_null()) names.push_back(params["name"]);
        auto addrs = to_vec(params, "addresses");
        if (params.contains("address") && !params["address"].is_null()) addrs.push_back(params["address"]);
        if (names.empty() && addrs.empty())
            return adapter_error(ctx, "at least one name or address required", "MISSING_PARAM");
        if (names.size() + addrs.size() > 2000)
            return adapter_error(ctx, "too many lookup items", "ITEM_LIMIT", json{{"max_items", 2000}});
        json items = json::array();
        json functions = json::array();
        for (const auto& nj : names) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            json item = {{"input", nj}, {"input_kind", "name"}};
            if (!nj.is_string()) {
                item["error"] = {{"code", "INVALID_ADDRESS"}, {"message", "name must be a string"}};
                items.push_back(std::move(item));
                continue;
            }
            std::string n = nj.get<std::string>();
            const function_record_t* found = nullptr;
            for (const auto& f : ws.snapshot->functions) {
                std::string fname = func_name(*ws.snapshot, ws.ov_names, f);
                if (fname == n) { found = &f; break; }
            }
            if (!found) if (auto* sy = find_sym_name(*ws.snapshot, n)) {
                if (sy->kind == symbol_kind_t::function || sy->kind == symbol_kind_t::export_symbol) {
                    if (auto* f = find_func_at(*ws.snapshot, sy->address.value))
                        found = f;
                }
            }
            if (!found) item["error"] = {{"code", "NOT_FOUND"}, {"message", "function not found"}};
            else {
                item["function"] = func_json(*ws.snapshot, ws.ov_names, *found);
                functions.push_back(item["function"]);
            }
            items.push_back(std::move(item));
        }
        for (const auto& aj : addrs) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            json item = {{"input", aj}, {"input_kind", "address"}};
            auto address = resolve_address(ws, aj);
            auto value = address ? snapshot_address_value(ws, *address) : std::nullopt;
            if (!value) item["error"] = {{"code", "INVALID_ADDRESS"}, {"message", "address is not mapped by the target"}};
            else {
                const function_record_t* found = find_func_at(*ws.snapshot, *value);
                if (!found) found = find_func_in(*ws.snapshot, *value);
                if (!found) item["error"] = {{"code", "NOT_FOUND"}, {"message", "function not found"}};
                else {
                    item["function"] = func_json(*ws.snapshot, ws.ov_names, *found);
                    functions.push_back(item["function"]);
                }
            }
            items.push_back(std::move(item));
        }
        return adapter_ok(ctx, {{"items", items}, {"functions", functions}, {"count", functions.size()}});
    }

    tool_result_t tool_int_convert(const json& params, const workspace_request_context_t& ctx) {
        if (!params.contains("value")) return adapter_error(ctx, "value required", "MISSING_PARAM");
        if (!params["value"].is_string() && !params["value"].is_number_unsigned() &&
            !params["value"].is_number_integer())
            return adapter_error(ctx, "value must be a non-negative integer or string", "INVALID_PARAM");
        if (params["value"].is_number_integer() && params["value"].get<std::int64_t>() < 0)
            return adapter_error(ctx, "value must be non-negative", "INVALID_PARAM");
        const std::string vs = params["value"].is_string() ? params["value"].get<std::string>() :
            params["value"].is_number_unsigned() ? std::to_string(params["value"].get<std::uint64_t>()) :
            std::to_string(params["value"].get<std::int64_t>());
        std::string from = params.value("from_format", "auto");
        std::string to = params.value("to_format", "hex");
        std::uint64_t v = 0;
        try {
            if (from == "auto") { if (vs.size()>2&&vs[0]=='0'&&(vs[1]=='x'||vs[1]=='X')) v = std::stoull(vs.substr(2),nullptr,16); else v = std::stoull(vs,nullptr,0); }
            else v = parse_int_val(vs, from);
        } catch (...) { return adapter_error(ctx, "failed to parse integer value", "PARSE_ERROR"); }
        json result = {{"input", vs}, {"output", fmt_int(v, to)}, {"decimal", std::to_string(v)}, {"hex", hex_str(v)}};
        return adapter_ok(ctx, result);
    }

    tool_result_t tool_list_funcs(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.ok()) return adapter_error(ctx, "no analysis snapshot available", "NO_SNAPSHOT");
        const std::uint64_t offset = bounded_param(params, "offset", 0, std::numeric_limits<std::uint64_t>::max());
        const std::uint64_t limit = bounded_param(params, "limit", 1000, kMaxPageItems);
        std::string filter = params.value("filter", "");
        json funcs = json::array(); std::uint64_t skipped = 0, count = 0;
        for (const auto& f : ws.snapshot->functions) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            std::string name = func_name(*ws.snapshot, ws.ov_names, f);
            if (!filter.empty() && name.find(filter) == std::string::npos) continue;
            if (skipped < offset) { ++skipped; continue; }
            if (count >= limit) break;
            funcs.push_back(func_json(*ws.snapshot, ws.ov_names, f)); ++count;
        }
        std::uint64_t total = 0;
        for (const auto& f : ws.snapshot->functions) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            if (!filter.empty() && func_name(*ws.snapshot, ws.ov_names, f).find(filter) == std::string::npos) continue;
            ++total;
        }
        return adapter_ok(ctx, {{"functions", funcs}, {"count", count}, {"total", total},
            {"offset", offset}, {"next_offset", offset + count < total ? json(offset + count) : json(nullptr)}});
    }

    tool_result_t tool_list_globals(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.ok()) return adapter_error(ctx, "no analysis snapshot available", "NO_SNAPSHOT");
        const std::uint64_t offset = bounded_param(params, "offset", 0, std::numeric_limits<std::uint64_t>::max());
        const std::uint64_t limit = bounded_param(params, "limit", 1000, kMaxPageItems);
        std::string filter = params.value("filter", "");
        json globals = json::array(); std::uint64_t skipped = 0, count = 0;
        for (const auto& s : ws.snapshot->symbols) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            if (s.kind != symbol_kind_t::data && s.kind != symbol_kind_t::metadata) continue;
            if (!filter.empty() && s.name.find(filter) == std::string::npos) continue;
            if (skipped < offset) { ++skipped; continue; }
            if (count >= limit) break;
            globals.push_back(sym_json(s)); ++count;
        }
        std::uint64_t total = 0;
        for (const auto& s : ws.snapshot->symbols) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            if ((s.kind == symbol_kind_t::data || s.kind == symbol_kind_t::metadata) &&
                (filter.empty() || s.name.find(filter) != std::string::npos)) ++total;
        }
        return adapter_ok(ctx, {{"globals", globals}, {"count", count}, {"total", total},
            {"offset", offset}, {"next_offset", offset + count < total ? json(offset + count) : json(nullptr)}});
    }

    tool_result_t tool_imports(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.has_image()) return adapter_error(ctx, "normalized image unavailable", "NO_IMAGE");
        std::string mod = params.value("module", "");
        const std::uint64_t offset = bounded_param(params, "offset", 0, std::numeric_limits<std::uint64_t>::max());
        const std::uint64_t limit = bounded_param(params, "limit", 1000, kMaxPageItems);
        json imps = json::array(); std::uint64_t skipped = 0, count = 0;
        for (const auto& imp : ws.normalized_image->imports) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            if (!mod.empty() && imp.library != mod) continue;
            if (skipped < offset) { ++skipped; continue; }
            if (count >= limit) break;
            json j = {{"library", imp.library}, {"address", hex_str(imp.address.value)},
                {"lookup_address", hex_str(imp.lookup_address.value)}, {"delayed", imp.delayed}};
            if (imp.name) j["name"] = *imp.name;
            if (imp.ordinal) j["ordinal"] = *imp.ordinal;
            imps.push_back(j); ++count;
        }
        std::uint64_t total = 0;
        for (const auto& imp : ws.normalized_image->imports) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            if (mod.empty() || imp.library == mod) ++total;
        }
        return adapter_ok(ctx, {{"imports", imps}, {"count", count}, {"total", total},
            {"offset", offset}, {"next_offset", offset + count < total ? json(offset + count) : json(nullptr)}});
    }

    tool_result_t tool_decompile(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.workspace)
            return adapter_error(ctx, "workspace is unavailable", "NO_WORKSPACE");
        const auto locator = decompiler_locator(
            ws, params.value("address", json()));
        if (!locator)
            return adapter_error(ctx,
                "address, function name, or managed token locator is required",
                "MISSING_PARAM",
                json{{"managed_locator", "cli|jvm|dalvik|token:<value>[@artifact]"}});
        if (auto stopped = stop_result(ctx)) return std::move(*stopped);
        auto producer = decompiler_ui_integration_t::production_for_workspace(
            ws.workspace);
        if (!producer)
            return adapter_error(ctx, producer.error().message,
                "NO_DECOMPILER",
                json{{"phase", producer.error().phase},
                     {"stable_code", producer.error().stable_code()}});
        auto cancellation = request_cancellation_source(ctx);
        request_cancellation_bridge_t bridge(ctx, cancellation);
        if (!bridge.ready())
            return adapter_error(ctx,
                "decompiler cancellation bridge capacity is exhausted",
                "RESOURCE_EXHAUSTED",
                json{{"resource", "decompiler_cancellation_bridge"},
                     {"capacity", 16}});
        auto resolved = producer.value()->resolve_entity_at(
            *locator, cancellation.token());
        if (!resolved) {
            const auto& error = resolved.error();
            const std::string code = error.deadline ? "DEADLINE_EXCEEDED" :
                error.cancellation ? "CANCELLED" :
                error.code == workspace_error_code_t::target_ambiguous
                    ? "AMBIGUOUS_ENTITY" :
                error.code == workspace_error_code_t::target_not_found
                    ? "ENTITY_NOT_FOUND" : "ENTITY_RESOLUTION_FAILED";
            return adapter_error(ctx, error.message, code,
                json{{"phase", error.phase},
                     {"stable_code", error.stable_code()}});
        }
        const auto binding = resolved.take_value();
        ws.publication = ws.workspace->analysis_publication();
        if (!ws.publication ||
            ws.publication->generation != binding.generation ||
            ws.publication->analysis_revision != binding.analysis_revision ||
            ws.publication->overlay_revision != binding.overlay_revision ||
            ws.workspace->overlay_revision() != binding.overlay_revision ||
            (ctx.analysis_revision != 0 &&
             ctx.analysis_revision != binding.analysis_revision) ||
            ctx.overlay_revision != binding.overlay_revision)
            return adapter_error(ctx, "decompiler entity revision changed",
                "STALE_ENTITY",
                json{{"generation", binding.generation},
                     {"analysis_revision", binding.analysis_revision},
                     {"overlay_revision", binding.overlay_revision}});
        auto result = producer.value()->decompile_entity(
            binding, decompiler_ui_invocation_source_t::mcp_request,
            decompiler_profile_id_t::balanced,
            params.value("use_cache", true)
                ? decompiler_pipeline_cache_mode_t::read_write
                : decompiler_pipeline_cache_mode_t::bypass,
            cancellation.token());
        ::diag::log_tagged_fmt("decompiler", "mcp_tool_decompile typed_pipeline invoked entity_kind=%u generation=%llu",
            static_cast<unsigned int>(binding.entity.kind),
            static_cast<unsigned long long>(binding.generation));
        if (!result) {
            const auto& error = result.error();
            const std::string code = error.deadline ? "DEADLINE_EXCEEDED" :
                error.cancellation ? "CANCELLED" : "DECOMPILE_FAILED";
            return adapter_error(ctx, error.message, code,
                json{{"phase", error.phase},
                     {"stable_code", error.stable_code()}});
        }
        if (auto stopped = stop_result(ctx)) return std::move(*stopped);
        const auto& d = result.value();
        if (!d.succeeded() || d.workspace_generation != binding.generation ||
            d.analysis_revision != binding.analysis_revision ||
            d.overlay_revision != binding.overlay_revision ||
            d.document->entity != binding.entity) {
            ::diag::log_tagged_fmt("decompiler", "mcp_tool_decompile typed_pipeline status=failed pipeline_status=%u used_legacy_fallback=%d",
                static_cast<unsigned int>(d.status),
                d.used_legacy_fallback ? 1 : 0);
            json diagnostics = json::array();
            for (const auto& diagnostic : d.diagnostics) {
                diagnostics.push_back({
                    {"code", static_cast<std::uint32_t>(diagnostic.code)},
                    {"localization_key", diagnostic.localization_key},
                    {"message", diagnostic.message},
                    {"retryable", diagnostic.retryable},
                });
            }
            return adapter_error(ctx,
                "typed decompiler pipeline did not produce a valid document",
                d.status == decompiler_pipeline_status_t::deadline_exceeded
                    ? "DEADLINE_EXCEEDED" :
                d.status == decompiler_pipeline_status_t::cancelled
                    ? "CANCELLED" : "DECOMPILE_FAILED",
                json{{"status", static_cast<std::uint32_t>(d.status)},
                     {"diagnostics", std::move(diagnostics)}});
        }
        constexpr std::size_t kMaxPseudocodeBytes = 512 * 1024;
        const bool pseudocode_truncated =
            d.rendered_text.size() > kMaxPseudocodeBytes;
        ::diag::log_tagged_fmt("decompiler", "mcp_tool_decompile typed_pipeline status=completed pseudocode_bytes=%zu used_legacy_fallback=%d cache_hit=%d",
            d.rendered_text.size(),
            d.used_legacy_fallback ? 1 : 0,
            d.cache_hit_stage.has_value() ? 1 : 0);
        const auto entity_locator = decompiler_entity_locator_text(ws, binding);
        if (!entity_locator)
            return adapter_error(ctx,
                "decompiler entity could not be represented by a stable locator",
                "ENTITY_LOCATOR_UNAVAILABLE",
                json{{"entity_kind", static_cast<std::uint32_t>(
                    binding.entity.kind)}});
        constexpr std::size_t kMaxSourceMappingBytes = 192 * 1024;
        bool source_mappings_truncated = false;
        auto source_mappings = decompiler_source_mappings(
            d, kMaxSourceMappingBytes, source_mappings_truncated);
        json j = {{"address", *entity_locator},
            {"name", decompiler_entity_name(binding.entity)},
            {"size", std::to_string(decompiler_entity_size(ws, binding))},
            {"pseudocode", pseudocode_truncated
                ? d.rendered_text.substr(0, kMaxPseudocodeBytes)
                : d.rendered_text},
            {"pseudocode_truncated", pseudocode_truncated},
            {"cache_hit", d.cache_hit_stage.has_value()},
            {"persistent_cache_hit", false}, {"elapsed_ms", d.elapsed_ms},
            {"entity_kind", static_cast<std::uint32_t>(binding.entity.kind)},
            {"generation", binding.generation},
            {"analysis_revision", binding.analysis_revision},
            {"overlay_revision", binding.overlay_revision},
            {"source_mappings", std::move(source_mappings)},
            {"source_mappings_truncated", source_mappings_truncated},
            {"used_legacy_fallback", d.used_legacy_fallback}};
        if (const auto prototype = decompiler_entity_prototype(binding.entity))
            j["prototype"] = *prototype;
        else
            j["prototype"] = nullptr;
        if (d.provider) {
            j["provider"] = {
                {"registration_id", d.provider->registration_id},
                {"provider_id", static_cast<std::uint32_t>(
                    d.provider->identity.provider)},
                {"provider_name", d.provider->identity.provider_name},
                {"provider_version", d.provider->identity.provider_version},
                {"worker_build_id", d.provider->identity.worker_build_id},
            };
        }
        json callees = json::array();
        constexpr std::size_t kMaxCalleeBytes = 64U * 1024U;
        std::size_t callee_bytes = 2;
        bool callees_truncated = false;
        if (const auto* native = std::get_if<
                native_decompiler_entity_identity_t>(&binding.entity.identity);
            native && ws.snapshot) {
            const auto function = std::find_if(
                ws.snapshot->functions.begin(), ws.snapshot->functions.end(),
                [native](const function_record_t& candidate) {
                    return candidate.id == native->function_id;
                });
            if (function != ws.snapshot->functions.end()) {
                for (const auto& edge : ws.snapshot->edges) {
                    if (edge.source.value < function->start.value ||
                        edge.source.value >= function->end.value ||
                        (edge.kind != edge_kind_t::call &&
                         edge.kind != edge_kind_t::tail_call &&
                         edge.kind != edge_kind_t::indirect))
                        continue;
                    json callee{{"address", hex_str(edge.target.value)}};
                    if (const auto* target = find_func_at(
                            *ws.snapshot, edge.target.value))
                        callee["name"] = func_name(
                            *ws.snapshot, ws.ov_names, *target);
                    const auto serialized = callee.dump().size() + 1U;
                    if (serialized > kMaxCalleeBytes -
                            (std::min)(kMaxCalleeBytes, callee_bytes)) {
                        callees_truncated = true;
                        break;
                    }
                    callee_bytes += serialized;
                    callees.push_back(std::move(callee));
                    if (callees.size() >= kMaxPageItems) {
                        callees_truncated = true;
                        break;
                    }
                }
            }
        }
        j["callees"] = std::move(callees);
        j["callees_truncated"] = callees_truncated;
        return adapter_ok(ctx, j);
    }

    tool_result_t tool_disasm(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.has_provider() || !ws.has_image())
            return adapter_error(ctx, "provider and normalized image required", "NO_PROVIDER");
        auto start = resolve_address(ws, params.value("address", json()));
        if (!start) return adapter_error(ctx, "valid address required", "MISSING_PARAM");
        if (!start->provider_offset) {
            if (ws.live()) return live_unsupported(ctx, "disasm", "live_virtual_to_provider_offset");
            return adapter_error(ctx, "address is not mapped to provider data", "INVALID_ADDRESS");
        }
        const std::uint64_t max_insn = bounded_param(params, "max_instructions", 100, 4096);
        if (auto stopped = stop_result(ctx)) return std::move(*stopped);
        cancellation_source_t cancellation = request_cancellation_source(ctx);
        const arch_format_options_t format_options;
        const bool x86 = ws.normalized_image->architecture == architecture_id_t::x86 ||
            ws.normalized_image->architecture == architecture_id_t::x86_64;
        std::unique_ptr<worker_owned_x86_decoder_t> x86_decoder;
        std::unique_ptr<worker_owned_arch_decoder_t> generic_decoder;
        if (x86) {
            auto created = worker_owned_x86_decoder_t::create(ws.normalized_image->architecture_mode);
            if (!created.has_value()) return adapter_error(ctx, "decoder creation failed", "DECODER_ERROR");
            x86_decoder = std::move(created.take_value());
        } else {
            arch_decode_budget_t budget;
            const std::uint64_t decoder_attempts = std::max<std::uint64_t>(1, max_insn);
            budget.max_decode_attempts = decoder_attempts;
            budget.max_instructions = decoder_attempts;
            budget.max_input_bytes = std::min<std::uint64_t>(ws.provider->size(),
                decoder_attempts * arch_decode_result_t::instruction_byte_capacity);
            budget.max_format_attempts = decoder_attempts;
            budget.max_format_input_bytes = budget.max_input_bytes;
            budget.max_formatted_instructions = decoder_attempts;
            budget.max_formatted_text_bytes = decoder_attempts *
                static_cast<std::uint64_t>(format_options.maximum_text_bytes);
            auto generic = default_arch_decoder_registry().create_worker(
                make_arch_decoder_key(*ws.normalized_image), budget, cancellation.token());
            if (!generic.has_value())
                return adapter_error(ctx, "no bounded decoder is registered for the target architecture", "DECODER_UNAVAILABLE",
                    json{{"architecture", static_cast<unsigned>(ws.normalized_image->architecture)},
                        {"architecture_mode", static_cast<unsigned>(ws.normalized_image->architecture_mode)},
                        {"backend", "unregistered"},
                        {"phase", generic.error().phase}});
            generic_decoder = std::move(generic.take_value());
        }
        json insns = json::array();
        std::uint64_t current_offset = *start->provider_offset;
        address_t current_address = start->address;
        std::uint64_t count = 0;
        std::string termination = "completed";
        while (count < max_insn && current_offset < ws.provider->size()) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            instruction_record_t instruction;
            std::string text;
            json format_error;
            if (x86) {
                x86_decode_request_t request;
                request.address = current_address;
                request.provider_offset = current_offset;
                request.runtime_address = current_address.value;
                request.image_base = ws.normalized_image->image_base;
                request.image_size = ws.normalized_image->image_size;
                request.available_bytes = static_cast<std::uint8_t>(std::min<std::uint64_t>(15, ws.provider->size() - current_offset));
                auto decoded = x86_decoder->decode_one(*ws.provider, request, cancellation.token());
                if (!decoded.has_value()) {
                    if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                    termination = "decode_failure";
                    break;
                }
                instruction = decoded.value().instruction;
                if (ws.image) {
                    auto formatted = x86_decoder->format_one(*ws.provider, *ws.image, instruction, {}, cancellation.token());
                    if (formatted.has_value()) text = formatted.value();
                    else {
                        if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                        format_error = formatter_error_json(formatted.error(), *ws.normalized_image, "x86_pe");
                    }
                }
            } else {
                arch_decode_request_t request;
                request.address = current_address;
                request.provider_offset = current_offset;
                request.runtime_address = current_address.value;
                request.image_base = ws.normalized_image->image_base;
                request.image_size = ws.normalized_image->image_size;
                request.available_bytes = static_cast<std::uint16_t>(std::min<std::uint64_t>(255, ws.provider->size() - current_offset));
                auto decoded = generic_decoder->decode_one(*ws.provider, request);
                if (!decoded.has_value()) {
                    if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                    termination = "decode_failure";
                    break;
                }
                instruction = decoded.value().instruction;
                auto formatted = generic_decoder->format_one(*ws.provider, request, decoded.value(), format_options);
                if (formatted.has_value()) text = formatted.value();
                else {
                    if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                    format_error = formatter_error_json(formatted.error(), *ws.normalized_image,
                        generic_decoder->registration().implementation_id);
                }
            }
            if (instruction.length == 0 || instruction.length > ws.provider->size() - current_offset) {
                termination = "invalid_instruction_length";
                break;
            }
            auto bytes = read_provider_bytes(*ws.provider, current_offset, instruction.length);
            if (bytes.size() != instruction.length) { termination = "read_failure"; break; }
            json item = {{"address", hex_str(current_address.value)}, {"size", instruction.length},
                {"bytes", bytes_to_hex(bytes.data(), bytes.size())}, {"mnemonic_id", instruction.mnemonic_id}};
            if (!text.empty()) item["text"] = text;
            if (!format_error.is_null()) item["format_error"] = std::move(format_error);
            if (instruction.flow_flags & flow_call) item["flow"] = "call";
            else if (instruction.flow_flags & flow_branch) item["flow"] = "branch";
            else if (instruction.flow_flags & flow_return) item["flow"] = "return";
            if (auto* comment = ws.ov_names.fc(current_address.value)) item["comment"] = *comment;
            insns.push_back(std::move(item));
            current_offset += instruction.length;
            current_address.value += instruction.length;
            ++count;
        }
        const std::string text_formatter = x86 ? (ws.image ? "x86_pe" : "structured_ir") :
            generic_decoder->registration().implementation_id;
        return adapter_ok(ctx, {{"instructions", insns}, {"count", count}, {"termination", termination},
            {"text_formatter", text_formatter}});
    }

    tool_result_t tool_xrefs_to(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.ok()) return adapter_error(ctx, "no analysis snapshot available", "NO_SNAPSHOT");
        auto address = resolve_address(ws, params.value("address", json()));
        const auto value = address ? snapshot_address_value(ws, *address) : std::nullopt;
        if (!value) return adapter_error(ctx, "valid address required", "MISSING_PARAM");
        const std::uint64_t limit = bounded_param(params, "limit", 100, 1000);
        std::string kind = params.value("kind", "all");
        json xrefs = json::array(); std::uint64_t count = 0;
        for (const auto& x : ws.snapshot->xrefs) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            if (x.target.value != *value) continue;
            if (kind != "all" && xref_k_str(x.kind) != kind) continue;
            if (count >= limit) break;
            xrefs.push_back(xref_json(x)); ++count;
        }
        return adapter_ok(ctx, {{"xrefs", xrefs}, {"count", count}, {"limit", limit}});
    }

    tool_result_t tool_xrefs_to_field(const json& params, const workspace_request_context_t& ctx) {
        std::string sn = params.value("struct_name", ""), fn = params.value("field_name", "");
        if (sn.empty() || fn.empty())
            return adapter_error(ctx, "struct_name and field_name required", "MISSING_PARAM");
        ws_state ws(ctx);
        if (!ws.ok() || !ws.normalized_image) return adapter_error(ctx, "snapshot and normalized image required", "NO_SNAPSHOT");
        if (!ws.overlay) return adapter_error(ctx, "overlay not available", "NO_OVERLAY");
        if (ws.live()) return live_unsupported(ctx, "xrefs_to_field", "live_type_application_xrefs");
        if (auto stopped = stop_result(ctx)) return std::move(*stopped);
        const auto declarations = declared_types(ws);
        const auto layout = resolve_struct_layout(sn, declarations, pointer_width_bytes(*ws.normalized_image));
        if (layout.error == "declared type was not found")
            return adapter_error(ctx, "declared type was not found", "TYPE_NOT_FOUND", json{{"struct_name", sn}});
        const auto field = std::find_if(layout.fields.begin(), layout.fields.end(), [&](const auto& candidate) {
            return candidate.name == fn;
        });
        if (field == layout.fields.end())
            return adapter_error(ctx, "field was not found in the declared type", "FIELD_NOT_FOUND",
                json{{"struct_name", sn}, {"field_name", fn}});
        if (!field->error.empty())
            return adapter_error(ctx, "field layout is unresolved", "TYPE_LAYOUT_UNRESOLVED",
                json{{"struct_name", sn}, {"field_name", fn}, {"layout_error", field->error}});
        const std::uint64_t limit = bounded_param(params, "limit", 100, 1000);
        std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> field_instances;
        std::uint64_t unmapped_applications = 0;
        const auto overlay = ws.overlay->snapshot();
        for (const auto& item : overlay.items) {
            const auto& operation = item.second;
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            if (operation.kind != overlay_operation_kind_t::type_application ||
                !type_application_matches(operation.type, sn)) continue;
            const auto base = snapshot_address_value(ws, operation.address);
            if (!base || *base > (std::numeric_limits<std::uint64_t>::max)() - field->offset) {
                ++unmapped_applications;
                continue;
            }
            field_instances[*base + field->offset].push_back(*base);
        }
        for (auto& entry : field_instances) {
            auto& bases = entry.second;
            std::sort(bases.begin(), bases.end());
            bases.erase(std::unique(bases.begin(), bases.end()), bases.end());
        }
        std::vector<const xref_record_t*> ordered_xrefs;
        ordered_xrefs.reserve(ws.snapshot->xrefs.size());
        for (const auto& xref : ws.snapshot->xrefs) ordered_xrefs.push_back(&xref);
        std::sort(ordered_xrefs.begin(), ordered_xrefs.end(), [](const auto* lhs, const auto* rhs) {
            return std::tie(lhs->source.value, lhs->target.value, lhs->kind, lhs->id) <
                std::tie(rhs->source.value, rhs->target.value, rhs->kind, rhs->id);
        });
        json xrefs = json::array();
        bool truncated = false;
        for (const auto* xref : ordered_xrefs) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            const auto found = field_instances.find(xref->target.value);
            if (found == field_instances.end()) continue;
            if (xrefs.size() >= limit) { truncated = true; break; }
            auto item = xref_json(*xref);
            item["field_address"] = hex_str(xref->target.value);
            item["field_offset"] = field->offset;
            json bases = json::array();
            for (const auto base : found->second) bases.push_back(hex_str(base));
            item["struct_instances"] = std::move(bases);
            xrefs.push_back(std::move(item));
        }
        return adapter_ok(ctx, {{"struct_name", sn}, {"field_name", fn}, {"field_offset", field->offset},
            {"xrefs", xrefs}, {"count", xrefs.size()}, {"limit", limit},
            {"typed_instances", field_instances.size()}, {"unmapped_applications", unmapped_applications},
            {"truncated", truncated}});
    }

    tool_result_t tool_callees(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.ok()) return adapter_error(ctx, "no analysis snapshot available", "NO_SNAPSHOT");
        auto address = resolve_address(ws, params.value("address", json()));
        const auto value = address ? snapshot_address_value(ws, *address) : std::nullopt;
        if (!value) return adapter_error(ctx, "valid address required", "MISSING_PARAM");
        bool inc_ind = params.value("include_indirect", false);
        auto* f = find_func_at(*ws.snapshot, *value);
        if (!f) f = find_func_in(*ws.snapshot, *value);
        if (!f) return adapter_error(ctx, "no function at address", "NOT_FOUND");
        json callees = json::array();
        for (const auto& e : ws.snapshot->edges) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            if (e.source.value < f->start.value || e.source.value >= f->end.value) continue;
            if (e.kind != edge_kind_t::call && e.kind != edge_kind_t::tail_call && e.kind != edge_kind_t::indirect) continue;
            if (!inc_ind && e.kind == edge_kind_t::indirect) continue;
            if (callees.size() >= 1000) break;
            json j = {{"address", hex_str(e.target.value)}, {"kind", edge_k_str(e.kind)}};
            if (auto* tf = find_func_at(*ws.snapshot, e.target.value))
                j["name"] = func_name(*ws.snapshot, ws.ov_names, *tf);
            callees.push_back(j);
        }
        return adapter_ok(ctx, {{"callees", callees}, {"count", callees.size()}});
    }

    tool_result_t tool_get_bytes(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.has_provider() || !ws.has_image()) return adapter_error(ctx, "provider and normalized image required", "NO_PROVIDER");
        auto address = resolve_address(ws, params.value("address", json()));
        if (!address) return adapter_error(ctx, "valid address required", "MISSING_PARAM");
        const std::uint64_t size = bounded_param(params, "size", 1, kMaxByteRead);
        if (size == 0) return adapter_error(ctx, "size must be greater than zero", "INVALID_PARAM");
        if (!address->provider_offset) {
            if (ws.live()) return live_unsupported(ctx, "get_bytes", "live_virtual_to_provider_offset");
            return adapter_error(ctx, "address is not mapped to provider data", "INVALID_ADDRESS");
        }
        if (auto stopped = stop_result(ctx)) return std::move(*stopped);
        auto bytes = read_provider_bytes(*ws.provider, *address->provider_offset, static_cast<std::size_t>(size));
        if (bytes.empty()) return adapter_error(ctx, "failed to read bytes", "READ_ERROR");
        json j = {{"address", hex_str(address->address.value)}, {"size", bytes.size()},
            {"hex", bytes_to_hex(bytes.data(), bytes.size())}, {"truncated", bytes.size() < size}};
        return adapter_ok(ctx, j);
    }

    tool_result_t tool_get_int(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.has_provider() || !ws.has_image()) return adapter_error(ctx, "provider and normalized image required", "NO_PROVIDER");
        auto address = resolve_address(ws, params.value("address", json()));
        if (!address) return adapter_error(ctx, "valid address required", "MISSING_PARAM");
        const std::uint8_t sz = static_cast<std::uint8_t>(bounded_param(params, "size", 4, 8));
        if (sz == 0) return adapter_error(ctx, "size must be between 1 and 8", "INVALID_PARAM");
        bool is_signed = params.value("signed", false);
        std::string endian = params.value("endian", "little");
        if (endian != "little" && endian != "big") return adapter_error(ctx, "invalid endian", "INVALID_PARAM");
        if (!address->provider_offset) {
            if (ws.live()) return live_unsupported(ctx, "get_int", "live_virtual_to_provider_offset");
            return adapter_error(ctx, "address is not mapped to provider data", "INVALID_ADDRESS");
        }
        auto bytes = read_provider_bytes(*ws.provider, *address->provider_offset, sz);
        if (bytes.size() < sz) return adapter_error(ctx, "insufficient bytes", "READ_ERROR");
        std::uint64_t v = 0;
        if (endian == "big") { for (std::size_t i = 0; i < sz; ++i) v = (v << 8) | bytes[i]; }
        else { for (std::size_t i = 0; i < sz; ++i) v |= static_cast<std::uint64_t>(bytes[i]) << (i * 8); }
        json j = {{"address", hex_str(address->address.value)}, {"size", sz}, {"value", v}, {"hex", hex_str(v)}};
        if (is_signed && sz > 0 && sz <= 8) {
            const std::uint64_t mask = (sz < 8) ? ((1ULL << (sz * 8)) - 1ULL) : ~0ULL;
            std::uint64_t sv = v & mask;
            if (sv & (1ULL << (sz * 8 - 1))) j["signed_value"] = static_cast<std::int64_t>(sv | ~mask);
            else j["signed_value"] = static_cast<std::int64_t>(sv);
        }
        return adapter_ok(ctx, j);
    }

    tool_result_t tool_get_string(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.ok() || !ws.normalized_image) return adapter_error(ctx, "snapshot and normalized image required", "NO_SNAPSHOT");
        auto address = resolve_address(ws, params.value("address", json()));
        const auto value = address ? snapshot_address_value(ws, *address) : std::nullopt;
        if (!value) return adapter_error(ctx, "valid address required", "MISSING_PARAM");
        const std::uint64_t max_len = bounded_param(params, "max_length", 4096, kMaxByteRead);
        if (max_len == 0) return adapter_error(ctx, "max_length must be greater than zero", "INVALID_PARAM");
        std::string enc = params.value("encoding", "auto");
        if (enc != "auto" && enc != "ascii" && enc != "utf8" && enc != "utf16_le")
            return adapter_error(ctx, "invalid string encoding", "INVALID_PARAM");
        for (const auto& sr : ws.snapshot->strings) {
            if (sr.address.value == *value && (enc == "auto" || enc == str_enc_str(sr.encoding)))
                return adapter_ok(ctx, str_json(sr));
        }
        if (!ws.has_provider()) return adapter_error(ctx, "provider required for raw string read", "NO_PROVIDER");
        if (!address->provider_offset) {
            if (ws.live()) return live_unsupported(ctx, "get_string", "live_virtual_to_provider_offset");
            return adapter_error(ctx, "address is not mapped to provider data", "INVALID_ADDRESS");
        }
        auto bytes = read_provider_bytes(*ws.provider, *address->provider_offset, static_cast<std::size_t>(max_len));
        if (bytes.empty()) return adapter_error(ctx, "failed to read bytes", "READ_ERROR");
        std::string result;
        const bool utf16 = enc == "utf16_le" || (enc == "auto" && bytes.size() >= 2 && bytes[1] == 0);
        if (utf16) {
            for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
                std::uint32_t code_point = static_cast<std::uint16_t>(bytes[i]) |
                    (static_cast<std::uint16_t>(bytes[i + 1]) << 8);
                if (code_point == 0) break;
                if (code_point >= 0xD800 && code_point <= 0xDBFF && i + 3 < bytes.size()) {
                    const std::uint16_t low = static_cast<std::uint16_t>(bytes[i + 2]) |
                        (static_cast<std::uint16_t>(bytes[i + 3]) << 8);
                    if (low >= 0xDC00 && low <= 0xDFFF) {
                        code_point = 0x10000 + ((code_point - 0xD800) << 10) + (low - 0xDC00);
                        i += 2;
                    }
                }
                if (code_point >= 0xD800 && code_point <= 0xDFFF) {
                    result += "\xEF\xBF\xBD";
                } else if (code_point <= 0x7F) result.push_back(static_cast<char>(code_point));
                else if (code_point <= 0x7FF) {
                    result.push_back(static_cast<char>(0xC0 | (code_point >> 6)));
                    result.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
                } else if (code_point <= 0xFFFF) {
                    result.push_back(static_cast<char>(0xE0 | (code_point >> 12)));
                    result.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
                    result.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
                } else {
                    result.push_back(static_cast<char>(0xF0 | (code_point >> 18)));
                    result.push_back(static_cast<char>(0x80 | ((code_point >> 12) & 0x3F)));
                    result.push_back(static_cast<char>(0x80 | ((code_point >> 6) & 0x3F)));
                    result.push_back(static_cast<char>(0x80 | (code_point & 0x3F)));
                }
            }
        } else {
            for (std::size_t i = 0; i < bytes.size() && bytes[i] != 0; ++i)
                result.push_back(static_cast<char>(bytes[i]));
        }
        result = json_safe_utf8(result);
        return adapter_ok(ctx, {{"address", hex_str(address->address.value)}, {"value", result},
            {"encoding", utf16 ? "utf16_le" : (enc == "auto" ? "ascii" : enc)}, {"length", result.size()},
            {"truncated", result.size() == max_len}});
    }

    tool_result_t tool_get_global_value(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.has_provider() || !ws.has_image()) return adapter_error(ctx, "provider and normalized image required", "NO_PROVIDER");
        auto address = resolve_address(ws, params.value("address", json()));
        if (!address) return adapter_error(ctx, "valid address required", "MISSING_PARAM");
        const std::uint8_t sz = static_cast<std::uint8_t>(bounded_param(params, "size", 8, 8));
        if (sz == 0) return adapter_error(ctx, "size must be between 1 and 8", "INVALID_PARAM");
        std::string as_type = params.value("as_type", "hex");
        if (!address->provider_offset) {
            if (ws.live()) return live_unsupported(ctx, "get_global_value", "live_virtual_to_provider_offset");
            return adapter_error(ctx, "address is not mapped to provider data", "INVALID_ADDRESS");
        }
        auto bytes = read_provider_bytes(*ws.provider, *address->provider_offset, sz);
        if (bytes.size() < sz) return adapter_error(ctx, "insufficient bytes", "READ_ERROR");
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < sz; ++i) v |= static_cast<std::uint64_t>(bytes[i]) << (i * 8);
        json j = {{"address", hex_str(address->address.value)}, {"size", sz}};
        if (as_type == "int") {
            const std::uint64_t mask = sz < 8 ? ((1ULL << (sz * 8)) - 1ULL) : ~0ULL;
            const std::uint64_t masked = v & mask;
            j["value"] = static_cast<std::int64_t>(masked & (1ULL << (sz * 8 - 1)) ? masked | ~mask : masked);
        }
        else if (as_type == "uint") j["value"] = v;
        else if (as_type == "hex") j["value"] = hex_str(v);
        else if (as_type == "bytes") j["value"] = bytes_to_hex(bytes.data(), bytes.size());
        else if (as_type == "ascii") { std::string s; for (auto b : bytes) if (b) s.push_back(static_cast<char>(b)); j["value"] = json_safe_utf8(s); }
        else if (as_type == "ptr") j["value"] = hex_str(v);
        else return adapter_error(ctx, "invalid as_type", "INVALID_PARAM");
        return adapter_ok(ctx, j);
    }

    tool_result_t tool_stack_frame(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.ok() || !ws.normalized_image) return adapter_error(ctx, "snapshot required", "NO_SNAPSHOT");
        if (!ctx.workspace) return adapter_error(ctx, "workspace unavailable", "NO_WORKSPACE");
        if (ws.live()) return live_unsupported(ctx, "stack_frame", "live_calling_convention_analysis");
        auto address = resolve_address(ws, params.value("address", json()));
        const auto value = address ? snapshot_address_value(ws, *address) : std::nullopt;
        if (!value) return adapter_error(ctx, "valid address required", "MISSING_PARAM");
        auto* f = find_func_at(*ws.snapshot, *value);
        if (!f) f = find_func_in(*ws.snapshot, *value);
        if (!f) return adapter_error(ctx, "no function at address", "NOT_FOUND");
        if (auto stopped = stop_result(ctx)) return std::move(*stopped);
        cancellation_source_t cancellation = request_cancellation_source(ctx);
        calling_convention_request_t request;
        request.function = f->start;
        request.expected_generation = ws.snapshot->generation;
        request.expected_analysis_revision = ws.snapshot->analysis_revision;
        request.expected_overlay_revision = ws.snapshot->overlay_revision;
        request.max_instruction_visits = 32768;
        request.max_evidence = 1024;
        request.max_stack_slots = 512;
        auto inferred = infer_calling_convention(*ctx.workspace, request, cancellation.token());
        if (!inferred.has_value()) {
            const auto& error = inferred.error();
            return adapter_error(ctx, error.message, error.deadline ? "DEADLINE_EXCEEDED" :
                error.cancellation ? "CANCELLED" : "STACK_FRAME_ERROR", json{{"phase", error.phase}});
        }
        if (auto stopped = stop_result(ctx)) return std::move(*stopped);
        const auto& result = inferred.value();
        std::unordered_map<std::int64_t, const overlay_operation_t*> declared_slots;
        if (ws.overlay) {
            const auto overlay = ws.overlay->snapshot();
            for (const auto& item : overlay.items) {
                const auto& operation = item.second;
                if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                if (operation.kind != overlay_operation_kind_t::stack_variable) continue;
                const auto variable_address = snapshot_address_value(ws, operation.address);
                if (!variable_address) continue;
                const auto* owner = find_func_in(*ws.snapshot, *variable_address);
                if (owner && owner->start.value == f->start.value)
                    declared_slots[operation.stack_offset] = &operation;
            }
        }
        auto slots = result.frame.slots;
        std::sort(slots.begin(), slots.end(), [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.offset, lhs.kind, lhs.base_reg, lhs.size) <
                std::tie(rhs.offset, rhs.kind, rhs.base_reg, rhs.size);
        });
        json slot_items = json::array();
        std::unordered_set<std::int64_t> inferred_offsets;
        for (const auto& slot : slots) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            inferred_offsets.insert(slot.offset);
            json item = {{"offset", slot.offset}, {"size", slot.size}, {"base_reg", slot.base_reg},
                {"access_width_bits", slot.access_width_bits}, {"kind", stack_slot_kind_string(slot.kind)},
                {"provenance", prov_str(slot.provenance)}, {"confidence", slot.confidence},
                {"is_argument", slot.is_argument}, {"is_spill", slot.is_spill}, {"is_local", slot.is_local},
                {"is_saved_register", slot.is_saved_register}, {"read", slot.read}, {"written", slot.written}};
            if (const auto declared = declared_slots.find(slot.offset); declared != declared_slots.end()) {
                item["name"] = declared->second->variable;
                item["type"] = declared->second->type;
                item["source"] = "inferred_and_declared";
            } else item["source"] = "inferred";
            slot_items.push_back(std::move(item));
        }
        std::vector<const overlay_operation_t*> supplemental_slots;
        supplemental_slots.reserve(declared_slots.size());
        for (const auto& [offset, operation] : declared_slots)
            if (inferred_offsets.find(offset) == inferred_offsets.end()) supplemental_slots.push_back(operation);
        std::sort(supplemental_slots.begin(), supplemental_slots.end(), [](const auto* lhs, const auto* rhs) {
            return std::tie(lhs->stack_offset, lhs->variable, lhs->type) <
                std::tie(rhs->stack_offset, rhs->variable, rhs->type);
        });
        for (const auto* operation : supplemental_slots) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            slot_items.push_back({{"offset", operation->stack_offset}, {"size", 0}, {"base_reg", 0},
                {"access_width_bits", 0}, {"kind", "declared"}, {"provenance", "user_definition"},
                {"confidence", 100}, {"is_argument", false}, {"is_spill", false}, {"is_local", false},
                {"is_saved_register", false}, {"read", false}, {"written", false},
                {"name", operation->variable}, {"type", operation->type}, {"source", "declared"}});
        }
        json saved_registers = json::array();
        if (params.value("include_saved_regs", true)) {
            for (const auto& preserved : result.frame.preserved_registers) {
                if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                saved_registers.push_back({{"reg", preserved.reg}, {"saved", preserved.saved},
                    {"restored", preserved.restored}, {"save_address", hex_str(preserved.save_rva)},
                    {"restore_address", hex_str(preserved.restore_rva)}, {"provenance", prov_str(preserved.provenance)},
                    {"confidence", preserved.confidence}});
            }
        }
        return adapter_ok(ctx, {{"function", hex_str(f->start.value)}, {"state", calling_convention_state_string(result.state)},
            {"abi", static_cast<unsigned>(result.abi)}, {"confidence", result.confidence},
            {"frame_size", result.frame.frame_size}, {"frame_size_known", result.frame.frame_size_known},
            {"observed_stack_extent", result.frame.observed_stack_extent}, {"stack_pointer_reg", result.frame.stack_pointer_reg},
            {"frame_pointer_reg", result.frame.frame_pointer_reg}, {"uses_frame_pointer", result.frame.uses_frame_pointer},
            {"has_shadow_space", result.frame.has_shadow_space}, {"shadow_space_size", result.frame.shadow_space_size},
            {"prologue_end", hex_str(result.frame.prologue_end_rva)}, {"epilogue_start", hex_str(result.frame.epilogue_start_rva)},
            {"slots", slot_items}, {"slot_count", slot_items.size()}, {"saved_registers", saved_registers},
            {"saved_register_count", saved_registers.size()}, {"bounded", result.bounded},
            {"instructions_analyzed", result.instructions_analyzed}});
    }

    tool_result_t tool_read_struct(const json& params, const workspace_request_context_t& ctx) {
        if (params.contains("fields"))
            return mcp_standalone::read_live_struct(params);
        ws_state ws(ctx);
        std::string struct_name = params.value("struct_name", "");
        if (struct_name.empty()) return adapter_error(ctx, "struct_name required", "MISSING_PARAM");
        if (!ws.has_provider() || !ws.has_image())
            return adapter_error(ctx, "provider and normalized image required", "NO_PROVIDER");
        if (!ws.overlay) return adapter_error(ctx, "overlay not available", "NO_OVERLAY");
        if (ws.live()) return live_unsupported(ctx, "read_struct", "live_virtual_to_provider_offset");
        auto address = resolve_address(ws, params.value("address", json()));
        if (!address) return adapter_error(ctx, "valid address required", "MISSING_PARAM");
        if (!address->provider_offset)
            return adapter_error(ctx, "address is not mapped to provider data", "INVALID_ADDRESS");
        if (auto stopped = stop_result(ctx)) return std::move(*stopped);
        const auto declarations = declared_types(ws);
        const auto layout = resolve_struct_layout(struct_name, declarations, pointer_width_bytes(*ws.normalized_image));
        if (layout.error == "declared type was not found")
            return adapter_error(ctx, "declared type was not found", "TYPE_NOT_FOUND", json{{"struct_name", struct_name}});
        if (layout.fields.empty() || layout.size == 0)
            return adapter_error(ctx, "declared type has no readable layout", "TYPE_LAYOUT_UNRESOLVED",
                json{{"struct_name", struct_name}, {"layout_error", layout.error}});
        if (layout.size > kMaxByteRead)
            return adapter_error(ctx, "declared type exceeds the bounded read limit", "READ_LIMIT",
                json{{"struct_name", struct_name}, {"layout_size", layout.size}, {"max_read_bytes", kMaxByteRead}});
        auto bytes = read_provider_bytes(*ws.provider, *address->provider_offset, static_cast<std::size_t>(layout.size));
        if (bytes.empty()) return adapter_error(ctx, "failed to read structure bytes", "READ_ERROR");
        json fields = json::array();
        const auto max_depth = bounded_param(params, "max_depth", 4, 16);
        if (!append_struct_fields(fields, layout, bytes.data(), bytes.size(), declarations,
                                  pointer_width_bytes(*ws.normalized_image), ws.normalized_image->endian,
                                  max_depth, ctx)) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            return adapter_error(ctx, "structure read stopped", "READ_CANCELLED");
        }
        return adapter_ok(ctx, {{"address", hex_str(address->address.value)}, {"struct_name", layout.name},
            {"layout_size", layout.size}, {"layout_alignment", layout.alignment}, {"layout_complete", layout.complete},
            {"layout_error", layout.error.empty() ? json(nullptr) : json(layout.error)}, {"bytes_read", bytes.size()},
            {"truncated", bytes.size() < layout.size}, {"max_depth", max_depth}, {"fields", fields},
            {"field_count", fields.size()}});
    }

    tool_result_t tool_search_structs(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.overlay) return adapter_error(ctx, "overlay not available", "NO_OVERLAY");
        std::string name = params.value("name", "");
        const std::uint64_t offset = bounded_param(params, "offset", 0, std::numeric_limits<std::uint64_t>::max());
        const std::uint64_t limit = bounded_param(params, "limit", 100, 1000);
        const auto declarations = declared_types(ws);
        const auto pointer_size = ws.normalized_image ? pointer_width_bytes(*ws.normalized_image) : 8;
        json structs = json::array(); std::uint64_t skipped = 0, total = 0;
        for (const auto& declaration : declarations) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            if (!name.empty() && declaration.name.find(name) == std::string::npos) continue;
            ++total;
            if (skipped < offset) { ++skipped; continue; }
            if (structs.size() >= limit) continue;
            const auto layout = resolve_struct_layout(declaration.name, declarations, pointer_size);
            json item = {{"name", declaration.name}, {"definition", declaration.definition},
                {"layout_size", layout.size}, {"layout_alignment", layout.alignment},
                {"layout_complete", layout.complete}, {"field_count", layout.fields.size()}};
            if (!layout.error.empty()) item["layout_error"] = layout.error;
            structs.push_back(std::move(item));
        }
        return adapter_ok(ctx, {{"structs", structs}, {"count", structs.size()}, {"total", total},
            {"offset", offset}, {"next_offset", offset + structs.size() < total ? json(offset + structs.size()) : json(nullptr)}});
    }

    tool_result_t tool_find_regex(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.ok()) return adapter_error(ctx, "snapshot required", "NO_SNAPSHOT");
        std::string pattern = params.value("pattern", "");
        if (pattern.empty()) return adapter_error(ctx, "pattern required", "MISSING_PARAM");
        if (pattern.size() > 512) return adapter_error(ctx, "pattern exceeds the bounded regex limit", "REGEX_LIMIT");
        std::string scope = params.value("scope", "all");
        if (scope != "all" && scope != "functions" && scope != "strings" && scope != "symbols")
            return adapter_error(ctx, "invalid regex scope", "INVALID_PARAM");
        const std::uint64_t offset = bounded_param(params, "offset", 0, std::numeric_limits<std::uint64_t>::max());
        const std::uint64_t limit = bounded_param(params, "limit", 100, kMaxPageItems);
        json results = json::array(); std::uint64_t skipped = 0, count = 0;
        try {
            std::regex re(pattern, std::regex_constants::ECMAScript | std::regex_constants::optimize);
            if (scope == "all" || scope == "functions") {
                for (const auto& f : ws.snapshot->functions) {
                    if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                    std::string n = func_name(*ws.snapshot, ws.ov_names, f);
                    if (n.size() <= 4096 && std::regex_search(n, re)) {
                        if (skipped < offset) { ++skipped; continue; }
                        if (count >= limit) break;
                        results.push_back({{"kind", "function"}, {"address", hex_str(f.start.value)}, {"name", n}}); ++count;
                    }
                }
            }
            if (scope == "all" || scope == "strings") {
                for (const auto& s : ws.snapshot->strings) {
                    if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                    if (s.value.size() <= 4096 && std::regex_search(s.value, re)) {
                        if (skipped < offset) { ++skipped; continue; }
                        if (count >= limit) break;
                        results.push_back({{"kind", "string"}, {"address", hex_str(s.address.value)}, {"value", s.value}}); ++count;
                    }
                }
            }
            if (scope == "all" || scope == "symbols") {
                for (const auto& s : ws.snapshot->symbols) {
                    if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                    if (s.name.size() <= 4096 && std::regex_search(s.name, re)) {
                        if (skipped < offset) { ++skipped; continue; }
                        if (count >= limit) break;
                        results.push_back({{"kind", "symbol"}, {"address", hex_str(s.address.value)}, {"name", s.name}}); ++count;
                    }
                }
            }
        } catch (const std::regex_error& e) {
            return adapter_error(ctx, std::string("regex error: ") + e.what(), "REGEX_ERROR");
        }
        return adapter_ok(ctx, {{"results", results}, {"count", count}, {"offset", offset}});
    }

    tool_result_t tool_find_bytes(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.has_provider() || !ws.has_image()) return adapter_error(ctx, "provider and normalized image required", "NO_PROVIDER");
        std::string hex_pat = params.value("hex_pattern", "");
        if (hex_pat.empty()) return adapter_error(ctx, "hex_pattern required", "MISSING_PARAM");
        const std::uint64_t offset = bounded_param(params, "offset", 0, std::numeric_limits<std::uint64_t>::max());
        const std::uint64_t limit = bounded_param(params, "limit", 100, kMaxPageItems);
        std::string mask_str = params.value("mask", "");
        auto pattern_bytes = parse_hex_bytes(hex_pat);
        auto mask_bytes = mask_str.empty() ? std::optional<std::vector<std::uint8_t>>(std::vector<std::uint8_t>{}) : parse_hex_bytes(mask_str);
        if (!pattern_bytes || !mask_bytes) return adapter_error(ctx, "invalid hexadecimal pattern or mask", "PARSE_ERROR");
        if (!mask_bytes->empty() && mask_bytes->size() != pattern_bytes->size())
            return adapter_error(ctx, "mask length must match pattern length", "INVALID_PARAM");
        if (pattern_bytes->size() > 65536)
            return adapter_error(ctx, "pattern exceeds the bounded search limit", "PATTERN_LIMIT");
        json results = json::array(); std::uint64_t skipped = 0, count = 0;
        const std::uint64_t chunk_size = 4 * 1024 * 1024;
        const std::uint64_t scan_size = std::min(ws.provider->size(), kMaxByteScan);
        for (std::uint64_t base = 0; base < scan_size && count < limit; base += chunk_size) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            const std::uint64_t read_start = base == 0 ? 0 : base - (pattern_bytes->size() - 1);
            const std::uint64_t read_end = std::min(scan_size, base + chunk_size + pattern_bytes->size() - 1);
            auto chunk = read_provider_bytes(*ws.provider, read_start, static_cast<std::size_t>(read_end - read_start));
            if (chunk.empty()) break;
            for (std::size_t i = static_cast<std::size_t>(base - read_start);
                 i + pattern_bytes->size() <= chunk.size(); ++i) {
                if ((i & 0xFFFU) == 0) if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                bool match = true;
                for (std::size_t j = 0; j < pattern_bytes->size() && match; ++j) {
                    const std::uint8_t mask = mask_bytes->empty() ? 0xFFU : (*mask_bytes)[j];
                    if ((chunk[i + j] & mask) != ((*pattern_bytes)[j] & mask)) match = false;
                }
                if (match) {
                    const std::uint64_t file_off = read_start + i;
                    const auto address = address_for_provider_offset(*ws.normalized_image, file_off);
                    if (!address) continue;
                    if (skipped < offset) { ++skipped; continue; }
                    if (count >= limit) break;
                    results.push_back({{"address", hex_str(address->value)}, {"file_offset", file_off}}); ++count;
                }
            }
        }
        return adapter_ok(ctx, {{"results", results}, {"count", count}, {"offset", offset},
            {"scan_bytes", scan_size}, {"scan_truncated", scan_size < ws.provider->size()}});
    }

    tool_result_t tool_find_insns(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.ok() || !ws.has_provider() || !ws.has_image())
            return adapter_error(ctx, "snapshot, provider, and normalized image required", "NO_SNAPSHOT");
        std::string mnem = params.value("mnemonic", "");
        if (mnem.empty()) return adapter_error(ctx, "mnemonic required", "MISSING_PARAM");
        const std::uint64_t offset = bounded_param(params, "offset", 0, std::numeric_limits<std::uint64_t>::max());
        const std::uint64_t limit = bounded_param(params, "limit", 100, kMaxPageItems);
        const std::string operand_pattern = params.value("operand_pattern", "");
        if (ws.live()) return live_unsupported(ctx, "find_insns", "live_instruction_formatter");
        const bool explicit_mnemonic_id = mnem.rfind("id:", 0) == 0;
        const auto parsed_mnemonic_id = parse_decimal(explicit_mnemonic_id ? mnem.substr(3) : mnem);
        if (explicit_mnemonic_id && !parsed_mnemonic_id)
            return adapter_error(ctx, "mnemonic id must be a decimal integer", "INVALID_PARAM");
        if (parsed_mnemonic_id && *parsed_mnemonic_id > (std::numeric_limits<std::uint16_t>::max)())
            return adapter_error(ctx, "mnemonic id exceeds the supported range", "INVALID_PARAM",
                json{{"maximum", (std::numeric_limits<std::uint16_t>::max)()}});
        const std::optional<std::uint16_t> mnemonic_id = parsed_mnemonic_id ?
            std::optional<std::uint16_t>(static_cast<std::uint16_t>(*parsed_mnemonic_id)) : std::nullopt;
        const bool x86 = ws.normalized_image->architecture == architecture_id_t::x86 ||
            ws.normalized_image->architecture == architecture_id_t::x86_64;
        std::vector<const instruction_record_t*> ordered;
        ordered.reserve(ws.snapshot->instructions.size());
        for (const auto& instruction : ws.snapshot->instructions) ordered.push_back(&instruction);
        std::sort(ordered.begin(), ordered.end(), [](const auto* lhs, const auto* rhs) {
            return std::tie(lhs->address.value, lhs->address.space, lhs->id) <
                std::tie(rhs->address.value, rhs->address.space, rhs->id);
        });
        if (mnemonic_id && operand_pattern.empty()) {
            json results = json::array();
            std::uint64_t skipped = 0, count = 0;
            for (const auto* instruction : ordered) {
                if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                if (instruction->mnemonic_id != *mnemonic_id) continue;
                if (skipped < offset) { ++skipped; continue; }
                if (count >= limit) break;
                results.push_back({{"address", hex_str(instruction->address.value)}, {"size", instruction->length},
                    {"mnemonic_id", instruction->mnemonic_id}, {"opcode_id", instruction->opcode_id}});
                ++count;
            }
            return adapter_ok(ctx, {{"results", results}, {"count", count}, {"offset", offset},
                {"limit", limit}, {"formatter", "instruction_id"}});
        }
        if (auto stopped = stop_result(ctx)) return std::move(*stopped);
        if (limit == 0)
            return adapter_ok(ctx, {{"results", json::array()}, {"count", 0}, {"offset", offset},
                {"limit", limit}, {"formatter", "not_invoked"}});
        cancellation_source_t cancellation = request_cancellation_source(ctx);
        const arch_format_options_t format_options;
        const std::uint64_t format_scan_limit = std::min<std::uint64_t>(
            static_cast<std::uint64_t>(ordered.size()), kMaxInstructionFormatScan);
        std::unique_ptr<worker_owned_x86_decoder_t> x86_decoder;
        std::unique_ptr<worker_owned_arch_decoder_t> generic_decoder;
        std::string formatter;
        if (x86 && ws.image) {
            auto decoder = worker_owned_x86_decoder_t::create(ws.normalized_image->architecture_mode);
            if (!decoder.has_value()) return adapter_error(ctx, "decoder creation failed", "DECODER_ERROR");
            x86_decoder = std::move(decoder.take_value());
            formatter = "x86_pe";
        } else {
            const std::uint64_t decoder_attempts = std::max<std::uint64_t>(1, format_scan_limit);
            arch_decode_budget_t budget;
            budget.max_decode_attempts = decoder_attempts;
            budget.max_instructions = decoder_attempts;
            budget.max_input_bytes = std::min<std::uint64_t>(ws.provider->size(),
                decoder_attempts * arch_decode_result_t::instruction_byte_capacity);
            budget.max_format_attempts = decoder_attempts;
            budget.max_format_input_bytes = budget.max_input_bytes;
            budget.max_formatted_instructions = decoder_attempts;
            budget.max_formatted_text_bytes = decoder_attempts *
                static_cast<std::uint64_t>(format_options.maximum_text_bytes);
            auto decoder = default_arch_decoder_registry().create_worker(
                make_arch_decoder_key(*ws.normalized_image), budget, cancellation.token());
            if (!decoder.has_value())
                return adapter_error(ctx, "no bounded formatter is registered for the target architecture", "DECODER_UNAVAILABLE",
                    json{{"operation", "find_insns"}, {"architecture", static_cast<unsigned>(ws.normalized_image->architecture)},
                        {"architecture_mode", static_cast<unsigned>(ws.normalized_image->architecture_mode)},
                        {"backend", "unregistered"}, {"phase", decoder.error().phase}});
            generic_decoder = std::move(decoder.take_value());
            formatter = generic_decoder->registration().implementation_id;
        }
        json results = json::array();
        json format_errors = json::array();
        std::uint64_t skipped = 0, count = 0, formatted = 0, format_error_count = 0;
        bool format_scan_truncated = false;
        const auto append_format_error = [&](const instruction_record_t& instruction, json error) {
            ++format_error_count;
            if (format_errors.size() >= kMaxInstructionFormatErrors) return;
            format_errors.push_back({{"address", hex_str(instruction.address.value)}, {"size", instruction.length},
                {"mnemonic_id", instruction.mnemonic_id}, {"opcode_id", instruction.opcode_id},
                {"error", std::move(error)}});
        };
        for (const auto* ins : ordered) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            if (mnemonic_id && ins->mnemonic_id != *mnemonic_id) continue;
            if (formatted >= format_scan_limit) { format_scan_truncated = true; break; }
            ++formatted;
            workspace_result_t<std::string> text = workspace_result_t<std::string>::failure(
                make_workspace_error(workspace_error_code_t::decode_failure,
                    "instruction formatter was not invoked", "ida_compat.find_insns.format"));
            if (x86_decoder) {
                text = x86_decoder->format_one(*ws.provider, *ws.image, *ins, {}, cancellation.token());
            } else {
                const auto provider_offset = provider_offset_for(*ws.normalized_image, ins->address, ins->length);
                if (!provider_offset) {
                    auto error = make_workspace_error(workspace_error_code_t::unsupported_address_space,
                        "instruction address is not mapped to provider bytes", "ida_compat.find_insns.format");
                    error.address = ins->address;
                    append_format_error(*ins, formatter_error_json(error, *ws.normalized_image, formatter));
                    continue;
                }
                arch_decode_request_t request;
                request.address = ins->address;
                request.provider_offset = *provider_offset;
                request.runtime_address = ins->address.value;
                request.image_base = ws.normalized_image->image_base;
                request.image_size = ws.normalized_image->image_size;
                request.available_bytes = static_cast<std::uint16_t>(std::min<std::uint64_t>(
                    arch_decode_result_t::instruction_byte_capacity, ws.provider->size() - *provider_offset));
                auto decoded = generic_decoder->decode_one(*ws.provider, request);
                if (!decoded.has_value()) {
                    if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                    append_format_error(*ins, formatter_error_json(decoded.error(), *ws.normalized_image, formatter));
                    continue;
                }
                text = generic_decoder->format_one(*ws.provider, request, decoded.value(), format_options);
            }
            if (!text.has_value()) {
                if (auto stopped = stop_result(ctx)) return std::move(*stopped);
                append_format_error(*ins, formatter_error_json(text.error(), *ws.normalized_image, formatter));
                continue;
            }
            const auto separator = text.value().find_first_of(" \t");
            const std::string mnemonic = text.value().substr(0, separator);
            if (!mnemonic_id && _stricmp(mnemonic.c_str(), mnem.c_str()) != 0) continue;
            if (!operand_pattern.empty() && text.value().find(operand_pattern) == std::string::npos) continue;
            if (skipped < offset) { ++skipped; continue; }
            if (count >= limit) break;
            json ij = {{"address", hex_str(ins->address.value)}, {"size", ins->length}, {"text", text.value()},
                {"mnemonic_id", ins->mnemonic_id}, {"opcode_id", ins->opcode_id}};
            results.push_back(ij); ++count;
        }
        return adapter_ok(ctx, {{"results", results}, {"count", count}, {"offset", offset}, {"limit", limit},
            {"formatter", formatter}, {"formatted", formatted}, {"format_scan_limit", format_scan_limit},
            {"format_scan_truncated", format_scan_truncated}, {"format_errors", format_errors},
            {"format_error_count", format_error_count},
            {"format_errors_truncated", format_error_count > format_errors.size()}});
    }

    tool_result_t tool_find(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.ok() || !ws.search_index) return adapter_error(ctx, "snapshot and search index required", "NO_SNAPSHOT");
        std::string query = params.value("query", "");
        if (query.empty()) return adapter_error(ctx, "query required", "MISSING_PARAM");
        const std::uint64_t offset = bounded_param(params, "offset", 0, std::numeric_limits<std::uint64_t>::max());
        const std::uint64_t limit = bounded_param(params, "limit", 100, kMaxPageItems);
        std::string kind = params.value("kind", "all");
        if (kind != "all" && kind != "function" && kind != "symbol" && kind != "string" && kind != "instruction" && kind != "data")
            return adapter_error(ctx, "invalid search kind", "INVALID_PARAM");
        cancellation_source_t cancellation;
        if (ctx.deadline_ms != 0) {
            const auto now = static_cast<std::uint64_t>(GetTickCount64());
            if (now >= ctx.deadline_ms) return adapter_error(ctx, "request deadline exceeded", "DEADLINE_EXCEEDED");
            cancellation.set_deadline(std::chrono::steady_clock::now() + std::chrono::milliseconds(ctx.deadline_ms - now));
        }
        json results = json::array();
        std::uint64_t search_offset = 0;
        std::uint64_t matched = 0;
        std::uint64_t total = 0;
        bool scan_truncated = false;
        constexpr std::uint64_t kSearchScanLimit = 100000;
        while (results.size() < limit && search_offset < kSearchScanLimit) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            auto page_result = ws.search_index->find_text(query, search_offset, 512, cancellation.token());
            if (!page_result.has_value()) {
                const auto& error = page_result.error();
                return adapter_error(ctx, error.message, error.deadline ? "DEADLINE_EXCEEDED" :
                    error.cancellation ? "CANCELLED" : "SEARCH_ERROR", json{{"phase", error.phase}});
            }
            const auto& page = page_result.value();
            total = page.total;
            if (page.hits.empty()) break;
            for (const auto& h : page.hits) {
                const char* hit_kind = "unknown";
                switch (h.kind) {
                case search_entity_kind_t::function: hit_kind = "function"; break;
                case search_entity_kind_t::symbol: hit_kind = "symbol"; break;
                case search_entity_kind_t::string: hit_kind = "string"; break;
                case search_entity_kind_t::instruction: hit_kind = "instruction"; break;
                case search_entity_kind_t::data_candidate: hit_kind = "data"; break;
                default: break;
                }
                if (kind != "all" && kind != hit_kind) continue;
                if (matched++ < offset) continue;
                if (results.size() >= limit) break;
                results.push_back({{"kind", hit_kind}, {"address", hex_str(h.address.value)}, {"text", h.text}});
            }
            search_offset += page.hits.size();
            if (search_offset >= total) break;
        }
        if (search_offset < total && search_offset >= kSearchScanLimit) scan_truncated = true;
        return adapter_ok(ctx, {{"results", results}, {"count", results.size()}, {"total", total},
            {"offset", offset}, {"scan_truncated", scan_truncated}});
    }

    tool_result_t tool_basic_blocks(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.ok() || !ws.normalized_image) return adapter_error(ctx, "snapshot required", "NO_SNAPSHOT");
        auto address = resolve_address(ws, params.value("address", json()));
        const auto value = address ? snapshot_address_value(ws, *address) : std::nullopt;
        if (!value) return adapter_error(ctx, "valid address required", "MISSING_PARAM");
        bool inc_insns = params.value("include_instructions", false);
        auto* f = find_func_at(*ws.snapshot, *value);
        if (!f) f = find_func_in(*ws.snapshot, *value);
        if (!f) return adapter_error(ctx, "no function at address", "NOT_FOUND");
        json blocks = json::array();
        const std::size_t block_limit = inc_insns ? 256 : 4096;
        const std::size_t instruction_limit = 256;
        for (const auto& b : ws.snapshot->blocks) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            if (b.function_id != f->id) continue;
            if (blocks.size() >= block_limit) break;
            json bj = block_json(b);
            if (inc_insns) {
                json insns = json::array();
                for (const auto& ins : ws.snapshot->instructions) {
                    if (insns.size() >= instruction_limit) break;
                    if (ins.address.value >= b.start.value && ins.address.value < b.end.value)
                        insns.push_back({{"address", hex_str(ins.address.value)}, {"size", ins.length}});
                }
                bj["instructions"] = insns;
            }
            blocks.push_back(bj);
        }
        return adapter_ok(ctx, {{"blocks", blocks}, {"count", blocks.size()},
            {"truncated", blocks.size() >= block_limit}});
    }

    tool_result_t tool_export_funcs(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.has_image()) return adapter_error(ctx, "normalized image unavailable", "NO_IMAGE");
        const std::uint64_t offset = bounded_param(params, "offset", 0, std::numeric_limits<std::uint64_t>::max());
        const std::uint64_t limit = bounded_param(params, "limit", 1000, kMaxPageItems);
        std::string filter = params.value("filter", "");
        json exports = json::array(); std::uint64_t skipped = 0, count = 0;
        for (const auto& exp : ws.normalized_image->exports) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            std::string name = exp.name.value_or("");
            if (!filter.empty() && name.find(filter) == std::string::npos) continue;
            if (skipped < offset) { ++skipped; continue; }
            if (count >= limit) break;
            json j = {{"address", hex_str(exp.address.value)}, {"ordinal", exp.ordinal}};
            if (exp.name) j["name"] = *exp.name;
            if (exp.forwarder) j["forwarder"] = *exp.forwarder;
            if (ws.snapshot) if (auto* f = find_func_at(*ws.snapshot, exp.address.value))
                j["function"] = func_name(*ws.snapshot, ws.ov_names, *f);
            exports.push_back(j); ++count;
        }
        std::uint64_t total = 0;
        for (const auto& exp : ws.normalized_image->exports) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            if (filter.empty() || exp.name.value_or("").find(filter) != std::string::npos) ++total;
        }
        return adapter_ok(ctx, {{"exports", exports}, {"count", count}, {"total", total},
            {"offset", offset}, {"next_offset", offset + count < total ? json(offset + count) : json(nullptr)}});
    }

    tool_result_t tool_callgraph(const json& params, const workspace_request_context_t& ctx) {
        ws_state ws(ctx);
        if (!ws.ok() || !ws.normalized_image) return adapter_error(ctx, "snapshot required", "NO_SNAPSHOT");
        auto address = resolve_address(ws, params.value("address", json()));
        const auto value = address ? snapshot_address_value(ws, *address) : std::nullopt;
        if (!value) return adapter_error(ctx, "valid address required", "MISSING_PARAM");
        const int depth = static_cast<int>(bounded_param(params, "depth", 1, 10));
        std::string direction = params.value("direction", "both");
        if (direction != "callers" && direction != "callees" && direction != "both")
            return adapter_error(ctx, "invalid callgraph direction", "INVALID_PARAM");
        const std::uint64_t limit = bounded_param(params, "limit", 500, 5000);
        auto* f = find_func_at(*ws.snapshot, *value);
        if (!f) f = find_func_in(*ws.snapshot, *value);
        if (!f) return adapter_error(ctx, "no function at address", "NOT_FOUND");
        std::unordered_set<std::uint64_t> visited;
        std::deque<std::pair<std::uint64_t, int>> queue;
        queue.emplace_back(f->start.value, 0);
        visited.insert(f->start.value);
        json nodes = json::array();
        json edges_arr = json::array(); std::uint64_t edge_count = 0;
        while (!queue.empty() && nodes.size() < limit) {
            if (auto stopped = stop_result(ctx)) return std::move(*stopped);
            auto [cur_rva, cur_depth] = queue.front(); queue.pop_front();
            auto* cf = find_func_at(*ws.snapshot, cur_rva);
            if (!cf) continue;
            nodes.push_back({{"address", hex_str(cur_rva)}, {"name", func_name(*ws.snapshot, ws.ov_names, *cf)}, {"depth", cur_depth}});
            if (cur_depth >= depth) continue;
            if (direction == "callers" || direction == "both") {
                for (const auto& x : ws.snapshot->xrefs) {
                    if (x.target.value != cur_rva) continue;
                    if (x.kind != xref_kind_t::call && x.kind != xref_kind_t::code) continue;
                    if (edge_count >= limit) break;
                    edges_arr.push_back({{"from", hex_str(x.source.value)}, {"to", hex_str(cur_rva)}, {"kind", "caller"}});
                    ++edge_count;
                    if (auto* sf = find_func_in(*ws.snapshot, x.source.value)) {
                        if (visited.insert(sf->start.value).second)
                            queue.emplace_back(sf->start.value, cur_depth + 1);
                    }
                }
            }
            if (direction == "callees" || direction == "both") {
                for (const auto& e : ws.snapshot->edges) {
                    if (e.source.value < cf->start.value || e.source.value >= cf->end.value) continue;
                    if (e.kind != edge_kind_t::call && e.kind != edge_kind_t::tail_call) continue;
                    if (edge_count >= limit) break;
                    edges_arr.push_back({{"from", hex_str(cur_rva)}, {"to", hex_str(e.target.value)}, {"kind", "callee"}});
                    ++edge_count;
                    if (auto* target = find_func_at(*ws.snapshot, e.target.value)) {
                        if (visited.insert(target->start.value).second)
                            queue.emplace_back(target->start.value, cur_depth + 1);
                    }
                }
            }
        }
        return adapter_ok(ctx, {{"nodes", nodes}, {"edges", edges_arr}, {"node_count", nodes.size()},
            {"edge_count", edge_count}, {"truncated", !queue.empty()}});
    }

    std::vector<read_tool_def_t> get_read_tool_defs() {
        return {
            {"lookup_funcs", tool_lookup_funcs},
            {"int_convert", tool_int_convert},
            {"list_funcs", tool_list_funcs},
            {"list_globals", tool_list_globals},
            {"imports", tool_imports},
            {"decompile", tool_decompile},
            {"disasm", tool_disasm},
            {"xrefs_to", tool_xrefs_to},
            {"xrefs_to_field", tool_xrefs_to_field},
            {"callees", tool_callees},
            {"get_bytes", tool_get_bytes},
            {"get_int", tool_get_int},
            {"get_string", tool_get_string},
            {"get_global_value", tool_get_global_value},
            {"stack_frame", tool_stack_frame},
            {"read_struct", tool_read_struct},
            {"search_structs", tool_search_structs},
            {"find_regex", tool_find_regex},
            {"find_bytes", tool_find_bytes},
            {"find_insns", tool_find_insns},
            {"find", tool_find},
            {"basic_blocks", tool_basic_blocks},
            {"export_funcs", tool_export_funcs},
            {"callgraph", tool_callgraph},
        };
    }

}
