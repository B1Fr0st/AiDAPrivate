#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "ida_compat_mut.hpp"

#include "../analysis/workspace/advanced_cfg.hpp"
#include "../analysis/workspace/analysis_workspace.hpp"
#include "../analysis/workspace/compact_ir.hpp"
#include "../analysis/workspace/overlay_journal.hpp"
#include "../analysis/workspace/type_recovery.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace mcp_standalone::ida_compat
{
    using json = nlohmann::json;
    using namespace aida::analysis;

    namespace
    {
        constexpr std::size_t k_max_items = 4096;
        constexpr std::size_t k_max_patch_bytes = 1U << 20;
        constexpr std::size_t k_max_transaction_patch_bytes = 16U << 20;
        constexpr std::size_t k_max_assembly_bytes = 64U << 10;
        constexpr std::size_t k_max_assembly_statements = 4096;
        constexpr std::size_t k_max_name_bytes = 4096;
        constexpr std::size_t k_max_type_bytes = 64U << 10;
        constexpr std::size_t k_max_comment_bytes = 256U << 10;
        constexpr std::size_t k_max_idempotency_key_bytes = 256;
        constexpr std::size_t k_max_output_bytes = 1U << 20;
        constexpr std::size_t k_max_hex_input_bytes = 4U << 20;

        std::string trim_copy(std::string value)
        {
            const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char c) {
                return std::isspace(c) != 0;
            });
            const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) {
                return std::isspace(c) != 0;
            }).base();
            if (first >= last)
                return {};
            return {first, last};
        }

        std::string bounded_string(std::string value, std::size_t limit)
        {
            if (value.size() > limit)
                value.resize(limit);
            return value;
        }

        std::optional<std::uint64_t> parse_unsigned_token(const std::string& text)
        {
            std::string token = trim_copy(text);
            if (token.empty() || token.front() == '-')
                return std::nullopt;
            if (token.front() == '+')
                token.erase(token.begin());
            if (token.empty())
                return std::nullopt;

            int base = 10;
            if (token.size() > 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
                base = 16;
                token.erase(0, 2);
            } else if (token.size() > 1 && (token.back() == 'h' || token.back() == 'H')) {
                base = 16;
                token.pop_back();
            }
            if (token.empty())
                return std::nullopt;

            std::uint64_t value = 0;
            const auto parsed = std::from_chars(token.data(), token.data() + token.size(), value, base);
            if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size())
                return std::nullopt;
            return value;
        }

        std::optional<std::uint64_t> json_unsigned(const json& value)
        {
            if (value.is_number_unsigned())
                return value.get<std::uint64_t>();
            if (value.is_number_integer()) {
                const auto signed_value = value.get<std::int64_t>();
                if (signed_value >= 0)
                    return static_cast<std::uint64_t>(signed_value);
            }
            if (value.is_string())
                return parse_unsigned_token(value.get<std::string>());
            return std::nullopt;
        }

        std::optional<std::int64_t> json_signed(const json& value)
        {
            if (value.is_number_integer())
                return value.get<std::int64_t>();
            if (value.is_number_unsigned()) {
                const auto unsigned_value = value.get<std::uint64_t>();
                if (unsigned_value <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
                    return static_cast<std::int64_t>(unsigned_value);
                return std::nullopt;
            }
            if (!value.is_string())
                return std::nullopt;

            std::string token = trim_copy(value.get<std::string>());
            if (token.empty())
                return std::nullopt;
            const bool negative = token.front() == '-';
            if (negative || token.front() == '+')
                token.erase(token.begin());
            const auto magnitude = parse_unsigned_token(token);
            if (!magnitude)
                return std::nullopt;
            const auto minimum_magnitude = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1ULL;
            if (negative) {
                if (*magnitude > minimum_magnitude)
                    return std::nullopt;
                if (*magnitude == minimum_magnitude)
                    return std::numeric_limits<std::int64_t>::min();
                return -static_cast<std::int64_t>(*magnitude);
            }
            if (*magnitude > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
                return std::nullopt;
            return static_cast<std::int64_t>(*magnitude);
        }

        std::optional<std::uint64_t> parse_addr(const json& value)
        {
            if (value.is_number_unsigned() || value.is_number_integer())
                return json_unsigned(value);
            if (!value.is_string())
                return std::nullopt;

            std::string token = trim_copy(value.get<std::string>());
            std::string lower;
            lower.reserve(token.size());
            for (const char c : token)
                lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            if (lower.rfind("rva:", 0) == 0 || lower.rfind("va:", 0) == 0)
                token.erase(0, lower.rfind("rva:", 0) == 0 ? 4 : 3);
            return parse_unsigned_token(token);
        }

        address_t make_rva(const std::uint64_t value)
        {
            address_t address;
            address.space = address_space_id_t::relative_virtual;
            address.value = value;
            return address;
        }

        std::size_t assembly_statement_count(const std::string& assembly)
        {
            std::size_t count = 0;
            std::size_t begin = 0;
            while (begin < assembly.size()) {
                const std::size_t end = assembly.find('\n', begin);
                const std::size_t length = (end == std::string::npos ? assembly.size() : end) - begin;
                std::string line = trim_copy(assembly.substr(begin, length));
                const std::size_t comment = line.find(';');
                if (comment != std::string::npos)
                    line = trim_copy(line.substr(0, comment));
                if (!line.empty())
                    ++count;
                if (end == std::string::npos)
                    break;
                begin = end + 1;
            }
            return count;
        }

        bool parse_hex_bytes(const std::string& source, std::vector<std::uint8_t>& bytes, std::string& error)
        {
            if (source.size() > k_max_hex_input_bytes) {
                error = "hex patch input exceeds 4MiB";
                return false;
            }

            int high_nibble = -1;
            for (std::size_t index = 0; index < source.size(); ++index) {
                const char c = source[index];
                if (std::isspace(static_cast<unsigned char>(c)) || c == ',' || c == ':' || c == '_' || c == '-') {
                    if (high_nibble != -1) {
                        error = "hex patch has an incomplete byte";
                        return false;
                    }
                    continue;
                }
                if (c == '0' && index + 1 < source.size() && (source[index + 1] == 'x' || source[index + 1] == 'X') && high_nibble == -1) {
                    ++index;
                    continue;
                }
                if (!std::isxdigit(static_cast<unsigned char>(c))) {
                    error = "hex patch contains a non-hexadecimal character";
                    return false;
                }

                const int nibble = std::isdigit(static_cast<unsigned char>(c))
                    ? c - '0'
                    : std::tolower(static_cast<unsigned char>(c)) - 'a' + 10;
                if (high_nibble == -1) {
                    high_nibble = nibble;
                } else {
                    bytes.push_back(static_cast<std::uint8_t>((high_nibble << 4) | nibble));
                    high_nibble = -1;
                    if (bytes.size() > k_max_patch_bytes) {
                        error = "patch exceeds 1MiB";
                        return false;
                    }
                }
            }
            if (high_nibble != -1) {
                error = "hex patch has an incomplete byte";
                return false;
            }
            if (bytes.empty()) {
                error = "patch bytes are empty";
                return false;
            }
            return true;
        }

        bool parse_patch_bytes(const json& value, std::vector<std::uint8_t>& bytes, std::string& error)
        {
            bytes.clear();
            if (value.is_string())
                return parse_hex_bytes(value.get<std::string>(), bytes, error);
            if (value.is_number_unsigned() || value.is_number_integer()) {
                const auto byte = json_unsigned(value);
                if (!byte || *byte > 0xFFU) {
                    error = "numeric patch byte must be between 0 and 255";
                    return false;
                }
                bytes.push_back(static_cast<std::uint8_t>(*byte));
                return true;
            }
            if (!value.is_array()) {
                error = "patch bytes must be a hexadecimal string, byte, or byte array";
                return false;
            }
            if (value.size() == 0) {
                error = "patch bytes are empty";
                return false;
            }
            if (value.size() > k_max_patch_bytes) {
                error = "patch exceeds 1MiB";
                return false;
            }
            bytes.reserve(value.size());
            for (const auto& entry : value) {
                const auto byte = json_unsigned(entry);
                if (!byte || *byte > 0xFFU) {
                    error = "byte array entries must be integers between 0 and 255";
                    return false;
                }
                bytes.push_back(static_cast<std::uint8_t>(*byte));
            }
            return true;
        }

        const json* find_field(const json& item, const json& params, const char* field)
        {
            if (item.is_object()) {
                const auto it = item.find(field);
                if (it != item.end())
                    return &(*it);
            }
            if (&item != &params && params.is_object()) {
                const auto it = params.find(field);
                if (it != params.end())
                    return &(*it);
            }
            return nullptr;
        }

        std::vector<json> normalize_items(const json& params, std::initializer_list<const char*> keys)
        {
            for (const char* key : keys) {
                const auto it = params.find(key);
                if (it == params.end())
                    continue;
                if (it->is_array())
                    return it->get<std::vector<json>>();
                return {*it};
            }
            return {params};
        }

        std::optional<std::chrono::steady_clock::time_point> context_deadline(const workspace_request_context_t& context)
        {
            if (context.deadline_ms == 0)
                return std::nullopt;
            const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
            if (context.deadline_ms <= now)
                return std::chrono::steady_clock::now();
            return std::chrono::steady_clock::now() + std::chrono::milliseconds(context.deadline_ms - now);
        }

        struct transaction_options_t
        {
            bool dry_run = false;
            std::optional<std::uint64_t> expected_revision;
            std::optional<std::string> idempotency_key;
        };

        struct transaction_options_result_t
        {
            std::optional<transaction_options_t> value;
            std::string message;
            std::string code;
        };

        transaction_options_result_t parse_transaction_options(const json& params)
        {
            const json* source = &params;
            const auto tx_it = params.find("aida_tx");
            if (tx_it != params.end()) {
                if (!tx_it->is_object())
                    return {{}, "aida_tx must be an object", "INVALID_PARAM"};
                source = &(*tx_it);
            }

            transaction_options_t options;
            if (const auto it = source->find("dry_run"); it != source->end()) {
                if (!it->is_boolean())
                    return {{}, "aida_tx.dry_run must be a boolean", "INVALID_PARAM"};
                options.dry_run = it->get<bool>();
            }
            if (const auto it = source->find("expected_revision"); it != source->end()) {
                const auto expected_revision = json_unsigned(*it);
                if (!expected_revision)
                    return {{}, "aida_tx.expected_revision must be a non-negative integer", "INVALID_PARAM"};
                options.expected_revision = *expected_revision;
            }
            if (const auto it = source->find("idempotency_key"); it != source->end()) {
                if (!it->is_string())
                    return {{}, "aida_tx.idempotency_key must be a string", "INVALID_PARAM"};
                const std::string key = it->get<std::string>();
                if (key.empty() || key.size() > k_max_idempotency_key_bytes)
                    return {{}, "aida_tx.idempotency_key must contain between 1 and 256 bytes", "LIMIT_EXCEEDED"};
                options.idempotency_key = key;
            }
            return {options, {}, {}};
        }

        bool has_target_selector(const json& params)
        {
            return params.contains("target") || params.contains("target_id") || params.contains("pid") || params.contains("session_id");
        }

        class mutation_call_t
        {
        public:
            mutation_call_t(const char* tool_name,
                            const workspace_request_context_t& context,
                            const transaction_options_t& options,
                            const std::size_t item_count,
                            const bool selector_supplied)
                : tool_name_(tool_name),
                  context_(context),
                  cancellation_(context_deadline(context)),
                  item_count_(item_count),
                  selector_supplied_(selector_supplied)
            {
                request_.dry_run = options.dry_run;
                request_.expected_revision = options.expected_revision;
                request_.idempotency_key = options.idempotency_key;
                if (!context_.workspace) {
                    missing_hook_ = "workspace_request_context.workspace";
                } else {
                    const auto overlay = context_.workspace->overlay();
                    overlay_ = overlay.get();
                    if (!overlay_)
                        missing_hook_ = "analysis_workspace.overlay";
                }
                if (item_count_ <= k_max_items) {
                    item_results_.reserve(item_count_);
                    for (std::size_t index = 0; index < item_count_; ++index)
                        item_results_.push_back({{"index", index}, {"success", false}});
                }
            }

            tool_result_t failure(const std::string& message, const std::string& code, const json& extra = json::object())
            {
                json payload = base_payload(false);
                payload["error"] = {{"code", code}, {"message", bounded_string(message, 256)}};
                for (auto it = extra.begin(); it != extra.end(); ++it)
                    payload[it.key()] = it.value();
                return tool_result_t::error(message, code, bounded_payload(std::move(payload)));
            }

            tool_result_t missing_hook(const std::string& hook)
            {
                const std::string message = "MISSING_HOOK: " + hook;
                for (std::size_t index = 0; index < item_results_.size(); ++index) {
                    if (!item_results_[index].contains("error"))
                        record_error(index, "MISSING_HOOK", message);
                }
                return failure(message, "MISSING_HOOK", {{"missing_hook", hook}});
            }

            bool require_address(const std::size_t index, const json& item, const json& params, std::uint64_t& address)
            {
                const json* field = find_field(item, params, "address");
                if (!field) {
                    record_error(index, "MISSING_PARAM", "address is required");
                    return false;
                }
                const auto parsed = parse_addr(*field);
                if (!parsed) {
                    record_error(index, "INVALID_PARAM", "address must be a non-negative integer or address string");
                    return false;
                }
                address = *parsed;
                return true;
            }

            bool require_unsigned(const std::size_t index,
                                  const json& item,
                                  const json& params,
                                  const char* field_name,
                                  const std::uint64_t maximum,
                                  std::uint64_t& value)
            {
                const json* field = find_field(item, params, field_name);
                if (!field) {
                    record_error(index, "MISSING_PARAM", std::string(field_name) + " is required");
                    return false;
                }
                const auto parsed = json_unsigned(*field);
                if (!parsed || *parsed == 0 || *parsed > maximum) {
                    record_error(index, "INVALID_PARAM", std::string(field_name) + " is outside the supported range");
                    return false;
                }
                value = *parsed;
                return true;
            }

            bool require_signed(const std::size_t index,
                                const json& item,
                                const json& params,
                                const char* field_name,
                                std::int64_t& value)
            {
                const json* field = find_field(item, params, field_name);
                if (!field) {
                    record_error(index, "MISSING_PARAM", std::string(field_name) + " is required");
                    return false;
                }
                const auto parsed = json_signed(*field);
                if (!parsed) {
                    record_error(index, "INVALID_PARAM", std::string(field_name) + " must be a signed integer");
                    return false;
                }
                value = *parsed;
                return true;
            }

            bool read_text(const std::size_t index,
                           const json& item,
                           const json& params,
                           const char* field_name,
                           const std::size_t maximum,
                           const bool required,
                           const bool allow_empty,
                           std::string& value)
            {
                const json* field = find_field(item, params, field_name);
                if (!field) {
                    if (!required) {
                        value.clear();
                        return true;
                    }
                    record_error(index, "MISSING_PARAM", std::string(field_name) + " is required");
                    return false;
                }
                if (!field->is_string()) {
                    record_error(index, "INVALID_PARAM", std::string(field_name) + " must be a string");
                    return false;
                }
                value = field->get<std::string>();
                if (value.size() > maximum) {
                    record_error(index, "LIMIT_EXCEEDED", std::string(field_name) + " exceeds its maximum size");
                    return false;
                }
                if (!allow_empty && value.empty()) {
                    record_error(index, "MISSING_PARAM", std::string(field_name) + " must not be empty");
                    return false;
                }
                if (value.find('\0') != std::string::npos) {
                    record_error(index, "INVALID_PARAM", std::string(field_name) + " must not contain NUL bytes");
                    return false;
                }
                return true;
            }

            bool read_optional_end(const std::size_t index,
                                   const json& item,
                                   const json& params,
                                   const std::uint64_t start,
                                   std::optional<address_t>& end)
            {
                const json* field = find_field(item, params, "end");
                if (!field)
                    return true;
                const auto parsed = parse_addr(*field);
                if (!parsed || *parsed <= start) {
                    record_error(index, "INVALID_PARAM", "end must be greater than address");
                    return false;
                }
                end = make_rva(*parsed);
                return true;
            }

            bool cancelled_or_expired() const
            {
                return context_.cancellation_requested() ||
                    (context_.deadline_ms != 0 && static_cast<std::uint64_t>(GetTickCount64()) >= context_.deadline_ms);
            }

            cancellation_token_t analysis_cancellation_token()
            {
                if (context_.cancellation_requested())
                    cancellation_.request_cancel();
                return cancellation_.token();
            }

            void record_cancelled(const std::size_t index)
            {
                if (!cancelled_or_expired()) {
                    record_error(index, "INVALID_PARAM", "mutation item is invalid");
                    return;
                }
                record_error(index,
                             context_.deadline_ms != 0 && static_cast<std::uint64_t>(GetTickCount64()) >= context_.deadline_ms
                                 ? "DEADLINE_EXCEEDED"
                                 : "CANCELLED",
                             context_.deadline_ms != 0 && static_cast<std::uint64_t>(GetTickCount64()) >= context_.deadline_ms
                                 ? "request deadline has expired"
                                 : "request cancellation was requested");
            }

            void record_item_error(const std::size_t index, const std::string& code, const std::string& message)
            {
                record_error(index, code, message);
            }

            bool add_operation(const std::size_t index, overlay_operation_t operation)
            {
                if (cancelled_or_expired()) {
                    record_cancelled(index);
                    return false;
                }
                if (request_.operations.size() >= k_max_items) {
                    record_error(index, "LIMIT_EXCEEDED", "too many operations; maximum is 4096");
                    return false;
                }
                operation_items_.push_back(index);
                request_.operations.push_back(std::move(operation));
                return true;
            }

            bool has_item_errors() const
            {
                return validation_failed_;
            }

            tool_result_t commit()
            {
                if (!missing_hook_.empty())
                    return missing_hook(missing_hook_);
                if (cancelled_or_expired()) {
                    mark_unresolved_cancelled();
                    return failure("mutation request was cancelled before transaction commit", "CANCELLED");
                }
                if (validation_failed_)
                    return failure("one or more mutation items are invalid; transaction was not started", "VALIDATION_FAILED");
                if (request_.operations.empty())
                    return failure("at least one mutation item is required", "MISSING_PARAM");
                if (request_.operations.size() > k_max_items)
                    return failure("too many operations; maximum is 4096", "LIMIT_EXCEEDED");

                std::size_t patch_bytes = 0;
                for (const auto& operation : request_.operations) {
                    if (operation.bytes.size() > k_max_patch_bytes)
                        return failure("patch exceeds 1MiB", "LIMIT_EXCEEDED");
                    if (operation.assembly.size() > k_max_assembly_bytes)
                        return failure("assembly text exceeds 64KiB", "LIMIT_EXCEEDED");
                    if (assembly_statement_count(operation.assembly) > k_max_assembly_statements)
                        return failure("assembly exceeds 4096 statements", "LIMIT_EXCEEDED");
                    patch_bytes += operation.bytes.size();
                    if (patch_bytes > k_max_transaction_patch_bytes)
                        return failure("total patch bytes exceed 16MiB", "LIMIT_EXCEEDED");
                }

                if (context_.cancellation_requested())
                    cancellation_.request_cancel();
                const auto result = overlay_->transact(request_, cancellation_.token());
                if (!result.has_value()) {
                    mark_unresolved_error("TX_FAILED", "overlay transaction failed");
                    return failure("overlay transaction failed", "TX_FAILED", {{"transaction_error", bounded_string(result.error().message, 256)}});
                }

                const auto& transaction = result.value();
                for (const auto& operation : transaction.operations) {
                    if (operation.index >= operation_items_.size())
                        continue;
                    const std::size_t item_index = operation_items_[operation.index];
                    json& item = item_results_[item_index];
                    item["success"] = true;
                    item["operation_index"] = operation.index;
                    item["entity_key"] = bounded_string(operation.entity_key, 96);
                    item["removes_value"] = operation.removes_value;
                }
                mark_unresolved_error("TX_RESULT_MISSING", "overlay transaction returned no result for this item");

                json payload = base_payload(transaction.committed);
                payload["dry_run"] = transaction.dry_run;
                payload["revision"] = transaction.revision;
                payload["transaction_id"] = transaction.transaction_id;
                payload["idempotent_replay"] = transaction.idempotent_replay;
                payload["operations"] = transaction.operations.size();
                return tool_result_t::ok(bounded_payload(std::move(payload)));
            }

        private:
            json provenance() const
            {
                return {
                    {"adapter", "ida_compat_mut"},
                    {"tool", tool_name_},
                    {"read_only", false},
                    {"mutation_mode", "reversible_overlay"},
                    {"target_binding", "workspace_request_context"},
                    {"target_selector_supplied", selector_supplied_},
                    {"ui_switched", false},
                    {"target_kind", context_.kind == target_kind_t::static_file ? "static_file" : "live_snapshot"},
                    {"live_write", false},
                    {"analysis_revision", context_.analysis_revision},
                    {"overlay_revision", context_.overlay_revision},
                    {"item_cap", k_max_items},
                    {"output_limit_bytes", k_max_output_bytes},
                    {"idempotency_key_supplied", request_.idempotency_key.has_value()}
                };
            }

            json base_payload(const bool committed) const
            {
                return {
                    {"committed", committed},
                    {"dry_run", request_.dry_run},
                    {"item_count", item_count_},
                    {"items", item_results_},
                    {"_meta", {{"aida", provenance()}}}
                };
            }

            json bounded_payload(json payload) const
            {
                if (payload.dump().size() <= k_max_output_bytes)
                    return payload;

                json compact_items = json::array();
                for (const auto& item : item_results_) {
                    json compact = {{"index", item.value("index", 0ULL)}, {"success", item.value("success", false)}};
                    if (item.contains("error") && item["error"].is_object())
                        compact["error_code"] = item["error"].value("code", "ERROR");
                    compact_items.push_back(std::move(compact));
                }
                payload["items"] = std::move(compact_items);
                payload["_meta"]["aida"]["output_truncated"] = true;
                return payload;
            }

            void record_error(const std::size_t index, const std::string& code, const std::string& message)
            {
                if (index >= item_results_.size())
                    return;
                item_results_[index] = {
                    {"index", index},
                    {"success", false},
                    {"error", {{"code", code}, {"message", bounded_string(message, 192)}}}
                };
                validation_failed_ = true;
            }

            void mark_unresolved_error(const std::string& code, const std::string& message)
            {
                for (std::size_t index = 0; index < item_results_.size(); ++index) {
                    if (!item_results_[index].value("success", false) && !item_results_[index].contains("error"))
                        record_error(index, code, message);
                }
            }

            void mark_unresolved_cancelled()
            {
                for (std::size_t index = 0; index < item_results_.size(); ++index) {
                    if (!item_results_[index].contains("error"))
                        record_cancelled(index);
                }
            }

            std::string tool_name_;
            const workspace_request_context_t& context_;
            overlay_journal_t* overlay_ = nullptr;
            overlay_transaction_request_t request_;
            cancellation_source_t cancellation_;
            std::size_t item_count_ = 0;
            bool selector_supplied_ = false;
            bool validation_failed_ = false;
            std::string missing_hook_;
            std::vector<json> item_results_;
            std::vector<std::size_t> operation_items_;
        };

        tool_result_t preflight_failure(const char* tool_name,
                                        const workspace_request_context_t& context,
                                        const std::string& message,
                                        const std::string& code)
        {
            mutation_call_t call(tool_name, context, {}, 0, false);
            return call.failure(message, code);
        }

        bool valid_batch(mutation_call_t& call, const std::vector<json>& items, tool_result_t& failure)
        {
            if (items.empty()) {
                failure = call.failure("at least one mutation item is required", "MISSING_PARAM");
                return false;
            }
            if (items.size() > k_max_items) {
                failure = call.failure("too many mutation items; maximum is 4096", "LIMIT_EXCEEDED");
                return false;
            }
            return true;
        }

        bool parse_integer_value(const json& value,
                                 const bool signed_type,
                                 const std::uint8_t width,
                                 std::uint64_t& encoded)
        {
            if (width == 0 || width > 8)
                return false;
            const std::uint64_t mask = width == 8 ? std::numeric_limits<std::uint64_t>::max() : ((1ULL << (width * 8U)) - 1ULL);
            if (!signed_type) {
                const auto parsed = json_unsigned(value);
                if (!parsed || *parsed > mask)
                    return false;
                encoded = *parsed;
                return true;
            }

            const auto parsed = json_signed(value);
            if (!parsed)
                return false;
            const std::int64_t minimum = width == 8
                ? std::numeric_limits<std::int64_t>::min()
                : -(1LL << (width * 8U - 1U));
            const std::int64_t maximum = width == 8
                ? std::numeric_limits<std::int64_t>::max()
                : (1LL << (width * 8U - 1U)) - 1LL;
            if (*parsed < minimum || *parsed > maximum)
                return false;
            encoded = static_cast<std::uint64_t>(*parsed) & mask;
            return true;
        }

        struct integer_type_t
        {
            const char* canonical = nullptr;
            std::uint8_t width = 0;
            bool signed_type = false;
        };

        std::optional<integer_type_t> parse_integer_type(const std::string& type)
        {
            static const std::unordered_map<std::string, integer_type_t> types = {
                {"u8", {"u8", 1, false}}, {"i8", {"i8", 1, true}},
                {"u16", {"u16", 2, false}}, {"i16", {"i16", 2, true}},
                {"u32", {"u32", 4, false}}, {"i32", {"i32", 4, true}},
                {"u64", {"u64", 8, false}}, {"i64", {"i64", 8, true}},
                {"byte", {"u8", 1, false}}, {"word", {"u16", 2, false}},
                {"dword", {"u32", 4, false}}, {"qword", {"u64", 8, false}}
            };
            std::string lower;
            lower.reserve(type.size());
            for (const char c : type)
                lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            const auto it = types.find(lower);
            if (it == types.end())
                return std::nullopt;
            return it->second;
        }

        bool rename_conflicts_with_existing(const workspace_request_context_t& context,
                                            const std::uint64_t address,
                                            const std::string& name,
                                            const std::unordered_map<std::string, std::uint64_t>& pending_names,
                                            std::string& source)
        {
            const auto pending = pending_names.find(name);
            if (pending != pending_names.end() && pending->second != address) {
                source = "request";
                return true;
            }
            if (!context.workspace) {
                source = "workspace_request_context.workspace";
                return true;
            }
            const auto publication = context.workspace->analysis_publication();
            if (!publication || !publication->snapshot) {
                source = "analysis_workspace.analysis_publication";
                return true;
            }
            for (const auto& symbol : publication->snapshot->symbols) {
                if (symbol.address.value != address && symbol.name == name) {
                    source = "analysis_snapshot.symbols";
                    return true;
                }
            }
            const auto overlay = context.workspace->overlay();
            if (!overlay) {
                source = "analysis_workspace.overlay";
                return true;
            }
            const auto snapshot = overlay->snapshot();
            for (const auto& entry : snapshot.items) {
                const overlay_operation_t& operation = entry.second;
                if (operation.kind == overlay_operation_kind_t::name && operation.address.value != address && operation.name == name) {
                    source = "overlay_journal";
                    return true;
                }
            }
            return false;
        }

        struct function_analysis_target_t
        {
            std::uint64_t function_address = 0;
            address_t overlay_start;
            address_t overlay_end;
        };

        struct function_target_resolution_t
        {
            std::optional<function_analysis_target_t> value;
            std::string code;
            std::string message;
        };

        std::string address_prefix(const json& value)
        {
            if (!value.is_string())
                return {};
            std::string prefix = value.get<std::string>();
            const auto separator = prefix.find(':');
            if (separator == std::string::npos)
                return {};
            prefix.resize(separator);
            std::transform(prefix.begin(), prefix.end(), prefix.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            return prefix;
        }

        std::optional<address_t> overlay_function_address(const analysis_workspace_t& workspace,
                                                           address_t address)
        {
            const auto& identity = workspace.identity();
            if (address.architecture == architecture_id_t::unknown)
                address.architecture = identity.architecture();
            if (address.mode == architecture_mode_t::unknown)
                address.mode = identity.architecture_mode();
            if (workspace.target_kind() != target_kind_t::live_snapshot) {
                if (address.space == address_space_id_t::live_virtual)
                    return std::nullopt;
                return address;
            }
            if (address.space == address_space_id_t::relative_virtual) {
                const std::uint64_t base = identity.module() ? identity.module()->base : identity.image_base();
                if (address.value > (std::numeric_limits<std::uint64_t>::max)() - base)
                    return std::nullopt;
                address.value += base;
                address.space = address_space_id_t::live_virtual;
            } else if (address.space == address_space_id_t::virtual_address) {
                address.space = address_space_id_t::live_virtual;
            }
            if (address.space != address_space_id_t::live_virtual)
                return std::nullopt;
            return address;
        }

        function_target_resolution_t resolve_function_target(const workspace_request_context_t& context,
                                                              const json& input)
        {
            if (!context.workspace)
                return {{}, "ANALYSIS_UNAVAILABLE", "analysis workspace is unavailable"};
            const auto publication = context.workspace->analysis_publication();
            const auto image = context.workspace->normalized_image();
            if (!publication || !publication->snapshot || !image)
                return {{}, "ANALYSIS_UNAVAILABLE", "published analysis snapshot and normalized image are required"};
            const auto parsed = parse_addr(input);
            if (!parsed)
                return {{}, "INVALID_PARAM", "address must be a non-negative integer or address string"};

            const bool live_target = context.workspace->target_kind() == target_kind_t::live_snapshot;
            const std::string prefix = address_prefix(input);
            address_space_id_t space = address_space_id_t::relative_virtual;
            if (prefix == "file") {
                return {{}, "UNSUPPORTED_ADDRESS", "function analysis does not accept file-offset addresses"};
            } else if (prefix == "va") {
                space = live_target
                    ? address_space_id_t::live_virtual : address_space_id_t::virtual_address;
            } else if (prefix != "rva" && !prefix.empty()) {
                return {{}, "INVALID_PARAM", "address prefix must be rva or va"};
            } else if (prefix.empty() && live_target) {
                space = address_space_id_t::live_virtual;
            } else if (prefix.empty() && image->image_base != 0 && *parsed >= image->image_base &&
                       *parsed - image->image_base < image->image_size) {
                space = address_space_id_t::virtual_address;
            }

            std::uint64_t function_address = *parsed;
            std::optional<std::uint64_t> alternate_function_address;
            if (live_target && space == address_space_id_t::relative_virtual) {
                const std::uint64_t base = context.workspace->identity().module()
                    ? context.workspace->identity().module()->base : context.workspace->identity().image_base();
                if (function_address > (std::numeric_limits<std::uint64_t>::max)() - base)
                    return {{}, "INVALID_PARAM", "RVA address overflows the live target address space"};
                alternate_function_address = function_address;
                function_address += base;
            } else if (!live_target && space == address_space_id_t::virtual_address) {
                if (function_address < image->image_base)
                    return {{}, "INVALID_PARAM", "virtual address precedes the image base"};
                alternate_function_address = function_address;
                function_address -= image->image_base;
            }

            const function_record_t* function = nullptr;
            for (const auto& candidate : publication->snapshot->functions) {
                if (candidate.start.value != function_address &&
                    (!alternate_function_address || candidate.start.value != *alternate_function_address))
                    continue;
                if (function != nullptr)
                    return {{}, "ANALYSIS_AMBIGUOUS", "multiple functions share the requested address"};
                function = &candidate;
            }
            if (function == nullptr)
                return {{}, "TARGET_NOT_FOUND", "requested address is not a function entry in the analysis snapshot"};
            if (function->end.value <= function->start.value)
                return {{}, "ANALYSIS_UNAVAILABLE", "function analysis record has an invalid range"};
            function_address = function->start.value;

            const auto start = overlay_function_address(*context.workspace, function->start);
            const auto end = overlay_function_address(*context.workspace, function->end);
            if (!start || !end || end->space != start->space || end->architecture != start->architecture ||
                end->mode != start->mode || end->value <= start->value) {
                return {{}, "UNSUPPORTED_ADDRESS", "function address cannot be represented by the reversible overlay"};
            }
            return {{function_analysis_target_t{function_address, *start, *end}}, {}, {}};
        }

        std::string analysis_failure_message(const workspace_error_t& error)
        {
            std::string message = "production analysis failed";
            if (!error.phase.empty())
                message += " during " + error.phase;
            if (!error.message.empty())
                message += ": " + error.message;
            return bounded_string(std::move(message), 192);
        }

        std::string inferred_type_binding(const recovered_type_t& recovered)
        {
            const auto& subject = recovered.subject;
            return "inferred." + std::to_string(static_cast<unsigned>(subject.kind)) + "." +
                std::to_string(subject.function_rva) + "." + std::to_string(subject.entity_id) + "." +
                std::to_string(subject.container_id) + "." + std::to_string(subject.reg) + "." +
                std::to_string(subject.stack_offset) + "." + std::to_string(subject.ordinal);
        }
    }

    tool_result_t tool_add_bookmark(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("add_bookmark", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("add_bookmark", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "bookmarks"});
        mutation_call_t call("add_bookmark", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        for (std::size_t index = 0; index < items.size(); ++index) {
            if (!items[index].is_object()) {
                call.record_item_error(index, "INVALID_PARAM", "mutation items must be objects");
                continue;
            }
            std::uint64_t address = 0;
            std::string name;
            std::string comment;
            if (!call.require_address(index, items[index], params, address) ||
                !call.read_text(index, items[index], params, "name", k_max_name_bytes, false, true, name) ||
                !call.read_text(index, items[index], params, "comment", k_max_comment_bytes, false, true, comment))
                continue;
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::bookmark;
            operation.address = make_rva(address);
            operation.name = std::move(name);
            operation.text = std::move(comment);
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_set_comments(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("set_comments", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("set_comments", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "comments"});
        mutation_call_t call("set_comments", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        for (std::size_t index = 0; index < items.size(); ++index) {
            if (!items[index].is_object()) {
                call.record_cancelled(index);
                continue;
            }
            std::uint64_t address = 0;
            std::string comment;
            if (!call.require_address(index, items[index], params, address) ||
                !call.read_text(index, items[index], params, "comment", k_max_comment_bytes, true, true, comment))
                continue;
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::comment;
            operation.address = make_rva(address);
            operation.text = std::move(comment);
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_patch_asm(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("patch_asm", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("patch_asm", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "patches"});
        mutation_call_t call("patch_asm", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        for (std::size_t index = 0; index < items.size(); ++index) {
            if (!items[index].is_object()) {
                call.record_cancelled(index);
                continue;
            }
            std::uint64_t address = 0;
            std::string assembly;
            if (!call.require_address(index, items[index], params, address) ||
                !call.read_text(index, items[index], params, "assembly", k_max_assembly_bytes, true, false, assembly))
                continue;
            if (assembly_statement_count(assembly) > k_max_assembly_statements) {
                call.record_cancelled(index);
                continue;
            }
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::assembly_patch;
            operation.address = make_rva(address);
            operation.assembly = std::move(assembly);
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_declare_type(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("declare_type", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("declare_type", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "types"});
        mutation_call_t call("declare_type", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        for (std::size_t index = 0; index < items.size(); ++index) {
            if (!items[index].is_object()) {
                call.record_cancelled(index);
                continue;
            }
            std::string name;
            std::string definition;
            if (!call.read_text(index, items[index], params, "name", k_max_name_bytes, true, false, name) ||
                !call.read_text(index, items[index], params, "definition", k_max_type_bytes, true, false, definition))
                continue;
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::type_declaration;
            operation.name = std::move(name);
            operation.text = std::move(definition);
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_define_func(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("define_func", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("define_func", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "functions"});
        mutation_call_t call("define_func", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        for (std::size_t index = 0; index < items.size(); ++index) {
            if (!items[index].is_object()) {
                call.record_cancelled(index);
                continue;
            }
            std::uint64_t address = 0;
            std::optional<address_t> end;
            if (!call.require_address(index, items[index], params, address) ||
                !call.read_optional_end(index, items[index], params, address, end))
                continue;
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::define_function;
            operation.address = make_rva(address);
            operation.end = end;
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_define_code(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("define_code", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("define_code", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "definitions"});
        mutation_call_t call("define_code", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        for (std::size_t index = 0; index < items.size(); ++index) {
            if (!items[index].is_object()) {
                call.record_cancelled(index);
                continue;
            }
            std::uint64_t address = 0;
            std::uint64_t size = 0;
            if (!call.require_address(index, items[index], params, address) ||
                !call.require_unsigned(index, items[index], params, "size", k_max_transaction_patch_bytes, size) ||
                size > std::numeric_limits<std::uint64_t>::max() - address) {
                if (size > std::numeric_limits<std::uint64_t>::max() - address)
                    call.record_cancelled(index);
                continue;
            }
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::define_code;
            operation.address = make_rva(address);
            operation.end = make_rva(address + size);
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_undefine(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("undefine", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("undefine", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "definitions"});
        mutation_call_t call("undefine", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        for (std::size_t index = 0; index < items.size(); ++index) {
            if (!items[index].is_object()) {
                call.record_cancelled(index);
                continue;
            }
            std::uint64_t address = 0;
            std::uint64_t size = 0;
            if (!call.require_address(index, items[index], params, address) ||
                !call.require_unsigned(index, items[index], params, "size", k_max_transaction_patch_bytes, size) ||
                size > std::numeric_limits<std::uint64_t>::max() - address) {
                if (size > std::numeric_limits<std::uint64_t>::max() - address)
                    call.record_cancelled(index);
                continue;
            }
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::undefine;
            operation.address = make_rva(address);
            operation.end = make_rva(address + size);
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_declare_stack(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("declare_stack", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("declare_stack", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "variables"});
        mutation_call_t call("declare_stack", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        for (std::size_t index = 0; index < items.size(); ++index) {
            if (!items[index].is_object()) {
                call.record_cancelled(index);
                continue;
            }
            std::uint64_t address = 0;
            std::int64_t offset = 0;
            std::string name;
            std::string type;
            if (!call.require_address(index, items[index], params, address) ||
                !call.require_signed(index, items[index], params, "offset", offset) ||
                !call.read_text(index, items[index], params, "name", k_max_name_bytes, true, false, name) ||
                !call.read_text(index, items[index], params, "type", k_max_type_bytes, true, false, type))
                continue;
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::stack_variable;
            operation.address = make_rva(address);
            operation.stack_offset = offset;
            operation.variable = std::move(name);
            operation.type = std::move(type);
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_delete_stack(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("delete_stack", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("delete_stack", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "offsets"});
        mutation_call_t call("delete_stack", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        for (std::size_t index = 0; index < items.size(); ++index) {
            std::uint64_t address = 0;
            std::int64_t offset = 0;
            if (items[index].is_object()) {
                if (!call.require_address(index, items[index], params, address) ||
                    !call.require_signed(index, items[index], params, "offset", offset))
                    continue;
            } else {
                const json* address_field = params.find("address") == params.end() ? nullptr : &params["address"];
                const auto parsed_address = address_field ? parse_addr(*address_field) : std::nullopt;
                const auto parsed_offset = json_signed(items[index]);
                if (!parsed_address || !parsed_offset) {
                    call.record_cancelled(index);
                    continue;
                }
                address = *parsed_address;
                offset = *parsed_offset;
            }
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::delete_stack_variable;
            operation.address = make_rva(address);
            operation.stack_offset = offset;
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_set_type(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("set_type", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("set_type", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "types"});
        mutation_call_t call("set_type", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        for (std::size_t index = 0; index < items.size(); ++index) {
            if (!items[index].is_object()) {
                call.record_cancelled(index);
                continue;
            }
            std::uint64_t address = 0;
            std::string type;
            if (!call.require_address(index, items[index], params, address) ||
                !call.read_text(index, items[index], params, "type", k_max_type_bytes, true, false, type))
                continue;
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::type_application;
            operation.address = make_rva(address);
            operation.type = std::move(type);
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_infer_types(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("infer_types", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("infer_types", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "addresses"});
        mutation_call_t call("infer_types", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;
        if (!ctx.workspace)
            return call.failure("analysis workspace is unavailable", "ANALYSIS_UNAVAILABLE");
        if (!ctx.workspace->overlay())
            return call.failure("reversible overlay journal is unavailable", "OVERLAY_UNAVAILABLE");

        std::unordered_set<std::uint64_t> requested_functions;
        std::size_t operation_count = 0;
        for (std::size_t index = 0; index < items.size(); ++index) {
            if (call.cancelled_or_expired()) {
                call.record_cancelled(index);
                continue;
            }
            const json* address = items[index].is_object()
                ? find_field(items[index], params, "address") : &items[index];
            if (address == nullptr) {
                call.record_item_error(index, "MISSING_PARAM", "address is required");
                continue;
            }
            const auto target = resolve_function_target(ctx, *address);
            if (!target.value) {
                call.record_item_error(index, target.code, target.message);
                continue;
            }
            if (!requested_functions.insert(target.value->function_address).second) {
                call.record_item_error(index, "DUPLICATE_ITEM", "function address appears more than once in this request");
                continue;
            }
            if (operation_count >= k_max_items) {
                call.record_item_error(index, "LIMIT_EXCEEDED", "type inference exceeds the 4096-operation transaction limit");
                continue;
            }

            const auto cfg = analyze_advanced_cfg(*ctx.workspace, target.value->function_address,
                                                  call.analysis_cancellation_token());
            if (!cfg) {
                call.record_item_error(index, "ANALYSIS_FAILED", analysis_failure_message(cfg.error()));
                continue;
            }
            if (call.cancelled_or_expired()) {
                call.record_cancelled(index);
                continue;
            }

            type_recovery_request_t request;
            request.function_rva = target.value->function_address;
            request.address_space = cfg.value().key.function_address.space;
            request.cfg_result = &cfg.value();
            request.limits.max_results = static_cast<std::uint64_t>(k_max_items - operation_count);
            const auto recovered = recover_types(*ctx.workspace, request, call.analysis_cancellation_token());
            if (!recovered) {
                call.record_item_error(index, "ANALYSIS_FAILED", analysis_failure_message(recovered.error()));
                continue;
            }
            if (recovered.value().cancelled || recovered.value().deadline_exceeded || call.cancelled_or_expired()) {
                call.record_cancelled(index);
                continue;
            }

            bool inferred = false;
            bool item_failed = false;
            std::unordered_set<std::string> bindings;
            for (const auto& type : recovered.value().types) {
                if (type.state != type_resolution_state_t::resolved ||
                    type.subject.function_rva != target.value->function_address)
                    continue;
                if (type.display_name.empty() || type.display_name.size() > k_max_type_bytes ||
                    type.display_name.find('\0') != std::string::npos) {
                    call.record_item_error(index, "INVALID_ANALYSIS_RESULT", "recovered type cannot be represented by the reversible overlay");
                    item_failed = true;
                    break;
                }
                std::string binding = inferred_type_binding(type);
                if (!bindings.insert(binding).second) {
                    call.record_item_error(index, "INVALID_ANALYSIS_RESULT", "type recovery returned duplicate subject bindings");
                    item_failed = true;
                    break;
                }
                overlay_operation_t operation;
                operation.kind = overlay_operation_kind_t::type_application;
                operation.address = target.value->overlay_start;
                operation.type = type.display_name;
                operation.variable = std::move(binding);
                if (!call.add_operation(index, std::move(operation))) {
                    item_failed = true;
                    break;
                }
                ++operation_count;
                inferred = true;
            }
            if (!item_failed && !inferred)
                call.record_item_error(index, "NO_INFERENCE", "production type recovery found no resolved types for the function");
        }
        return call.commit();
    }

    tool_result_t tool_analyze_funcs(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("analyze_funcs", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("analyze_funcs", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "addresses"});
        mutation_call_t call("analyze_funcs", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;
        if (!ctx.workspace)
            return call.failure("analysis workspace is unavailable", "ANALYSIS_UNAVAILABLE");
        if (!ctx.workspace->overlay())
            return call.failure("reversible overlay journal is unavailable", "OVERLAY_UNAVAILABLE");

        std::unordered_set<std::uint64_t> requested_functions;
        for (std::size_t index = 0; index < items.size(); ++index) {
            if (call.cancelled_or_expired()) {
                call.record_cancelled(index);
                continue;
            }
            const json* address = items[index].is_object()
                ? find_field(items[index], params, "address") : &items[index];
            if (address == nullptr) {
                call.record_item_error(index, "MISSING_PARAM", "address is required");
                continue;
            }
            const auto target = resolve_function_target(ctx, *address);
            if (!target.value) {
                call.record_item_error(index, target.code, target.message);
                continue;
            }
            if (!requested_functions.insert(target.value->function_address).second) {
                call.record_item_error(index, "DUPLICATE_ITEM", "function address appears more than once in this request");
                continue;
            }

            const auto analysis = analyze_advanced_cfg(*ctx.workspace, target.value->function_address,
                                                       call.analysis_cancellation_token());
            if (!analysis) {
                call.record_item_error(index, "ANALYSIS_FAILED", analysis_failure_message(analysis.error()));
                continue;
            }
            if (call.cancelled_or_expired()) {
                call.record_cancelled(index);
                continue;
            }
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::define_function;
            operation.address = target.value->overlay_start;
            operation.end = target.value->overlay_end;
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_rename(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("rename", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("rename", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "names"});
        mutation_call_t call("rename", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        if (transaction.value->dry_run) {
            if (!ctx.workspace)
                return call.missing_hook("workspace_request_context.workspace");
            const auto publication = ctx.workspace->analysis_publication();
            if (!publication || !publication->snapshot)
                return call.missing_hook("analysis_workspace.analysis_publication");
            if (!ctx.workspace->overlay())
                return call.missing_hook("analysis_workspace.overlay");
        }

        std::unordered_map<std::string, std::uint64_t> pending_names;
        for (std::size_t index = 0; index < items.size(); ++index) {
            if (!items[index].is_object()) {
                call.record_cancelled(index);
                continue;
            }
            std::uint64_t address = 0;
            std::string name;
            if (!call.require_address(index, items[index], params, address) ||
                !call.read_text(index, items[index], params, "name", k_max_name_bytes, true, false, name))
                continue;
            if (transaction.value->dry_run) {
                std::string source;
                if (rename_conflicts_with_existing(ctx, address, name, pending_names, source)) {
                    call.record_item_error(index, "CONFLICT", "name conflicts with " + source);
                    continue;
                }
            }
            pending_names.emplace(name, address);
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::name;
            operation.address = make_rva(address);
            operation.name = std::move(name);
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_patch(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("patch", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("patch", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "patches"});
        mutation_call_t call("patch", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        for (std::size_t index = 0; index < items.size(); ++index) {
            if (!items[index].is_object()) {
                call.record_cancelled(index);
                continue;
            }
            std::uint64_t address = 0;
            if (!call.require_address(index, items[index], params, address))
                continue;
            const json* value = find_field(items[index], params, "bytes");
            if (!value)
                value = find_field(items[index], params, "hex_string");
            if (!value) {
                call.record_cancelled(index);
                continue;
            }
            std::vector<std::uint8_t> bytes;
            std::string error;
            if (!parse_patch_bytes(*value, bytes, error)) {
                call.record_cancelled(index);
                continue;
            }
            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::byte_patch;
            operation.address = make_rva(address);
            operation.bytes = std::move(bytes);
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    tool_result_t tool_put_int(const json& params, const workspace_request_context_t& ctx)
    {
        if (!params.is_object())
            return preflight_failure("put_int", ctx, "tool parameters must be an object", "INVALID_PARAM");
        const auto transaction = parse_transaction_options(params);
        if (!transaction.value)
            return preflight_failure("put_int", ctx, transaction.message, transaction.code);
        const auto items = normalize_items(params, {"items", "patches"});
        mutation_call_t call("put_int", ctx, *transaction.value, items.size(), has_target_selector(params));
        tool_result_t failure;
        if (!valid_batch(call, items, failure))
            return failure;

        for (std::size_t index = 0; index < items.size(); ++index) {
            if (!items[index].is_object()) {
                call.record_item_error(index, "INVALID_PARAM", "put_int items must be objects");
                continue;
            }
            std::uint64_t address = 0;
            if (!call.require_address(index, items[index], params, address))
                continue;
            const json* value = find_field(items[index], params, "value");
            if (!value) {
                call.record_item_error(index, "MISSING_PARAM", "value is required");
                continue;
            }

            integer_type_t type = {"u32", 4, false};
            if (const json* ty = find_field(items[index], params, "ty")) {
                if (!ty->is_string()) {
                    call.record_item_error(index, "INVALID_PARAM", "ty must be a string");
                    continue;
                }
                const auto parsed_type = parse_integer_type(ty->get<std::string>());
                if (!parsed_type) {
                    call.record_item_error(index, "INVALID_PARAM", "ty must be one of i8, u8, i16, u16, i32, u32, i64, or u64");
                    continue;
                }
                type = *parsed_type;
            } else if (const json* size = find_field(items[index], params, "size")) {
                const auto parsed_size = json_unsigned(*size);
                if (!parsed_size || (*parsed_size != 1 && *parsed_size != 2 && *parsed_size != 4 && *parsed_size != 8)) {
                    call.record_item_error(index, "INVALID_PARAM", "size must be 1, 2, 4, or 8");
                    continue;
                }
                type = {
                    *parsed_size == 1 ? "u8" : *parsed_size == 2 ? "u16" : *parsed_size == 4 ? "u32" : "u64",
                    static_cast<std::uint8_t>(*parsed_size),
                    false
                };
            }
            if (const json* size = find_field(items[index], params, "size")) {
                const auto parsed_size = json_unsigned(*size);
                if (!parsed_size || *parsed_size != type.width) {
                    call.record_item_error(index, "INVALID_PARAM", "size must match ty");
                    continue;
                }
            }

            std::string endian = "little";
            if (const json* endian_field = find_field(items[index], params, "endian")) {
                if (!endian_field->is_string()) {
                    call.record_item_error(index, "INVALID_PARAM", "endian must be little or big");
                    continue;
                }
                endian = endian_field->get<std::string>();
                std::transform(endian.begin(), endian.end(), endian.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                if (endian != "little" && endian != "big") {
                    call.record_item_error(index, "INVALID_PARAM", "endian must be little or big");
                    continue;
                }
            }

            std::uint64_t encoded = 0;
            if (!parse_integer_value(*value, type.signed_type, type.width, encoded)) {
                call.record_item_error(index, "INVALID_PARAM", "value is outside the range for ty");
                continue;
            }
            std::vector<std::uint8_t> bytes(type.width);
            for (std::size_t byte = 0; byte < bytes.size(); ++byte) {
                const std::size_t shift_index = endian == "big" ? bytes.size() - byte - 1 : byte;
                bytes[byte] = static_cast<std::uint8_t>((encoded >> (shift_index * 8U)) & 0xFFU);
            }

            overlay_operation_t operation;
            operation.kind = overlay_operation_kind_t::integer_patch;
            operation.address = make_rva(address);
            operation.bytes = std::move(bytes);
            operation.integer_type = type.canonical;
            operation.integer_value = value->is_string() ? bounded_string(value->get<std::string>(), 128) : value->dump();
            call.add_operation(index, std::move(operation));
        }
        return call.commit();
    }

    std::vector<mut_tool_def_t> get_mutation_tool_defs()
    {
        return {
            {"add_bookmark", tool_add_bookmark, false},
            {"set_comments", tool_set_comments, false},
            {"patch_asm", tool_patch_asm, false},
            {"declare_type", tool_declare_type, false},
            {"define_func", tool_define_func, false},
            {"define_code", tool_define_code, false},
            {"undefine", tool_undefine, false},
            {"declare_stack", tool_declare_stack, false},
            {"delete_stack", tool_delete_stack, false},
            {"set_type", tool_set_type, false},
            {"infer_types", tool_infer_types, false},
            {"analyze_funcs", tool_analyze_funcs, false},
            {"rename", tool_rename, false},
            {"patch", tool_patch, false},
            {"put_int", tool_put_int, false}
        };
    }

}
