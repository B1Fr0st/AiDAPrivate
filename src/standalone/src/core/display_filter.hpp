#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <cctype>
#include <algorithm>
#include <functional>

namespace display_filter {

struct packet_fields_t {
    uint32_t pid = 0;
    uint8_t protocol = 0;
    uint8_t direction = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t payload_size = 0;
    std::string src_ip;
    std::string dst_ip;
    std::string protocol_label;
    std::string http_method;
    int http_status = 0;
    std::string dns_query;
    std::string summary;
    std::string host;
};

enum class token_type {
    field,
    op,
    value,
    logical_and,
    logical_or,
    logical_not,
    lparen,
    rparen,
    eof
};

struct token_t {
    token_type type = token_type::eof;
    std::string value;
};

inline std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

inline bool is_ident_start(char c) {
    return std::isalpha(static_cast<unsigned char>(c)) || c == '_';
}

inline bool is_ident_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.';
}

inline std::vector<token_t> tokenize(const std::string& input) {
    std::vector<token_t> tokens;
    size_t i = 0;
    size_t len = input.size();

    while (i < len) {
        char c = input[i];

        if (std::isspace(static_cast<unsigned char>(c))) {
            ++i;
            continue;
        }

        if (c == '(' ) {
            tokens.push_back({token_type::lparen, "("});
            ++i;
            continue;
        }

        if (c == ')') {
            tokens.push_back({token_type::rparen, ")"});
            ++i;
            continue;
        }

        if (c == '!' && (i + 1 >= len || input[i + 1] != '=')) {
            tokens.push_back({token_type::logical_not, "!"});
            ++i;
            continue;
        }

        if (c == '&' && i + 1 < len && input[i + 1] == '&') {
            tokens.push_back({token_type::logical_and, "&&"});
            i += 2;
            continue;
        }

        if (c == '|' && i + 1 < len && input[i + 1] == '|') {
            tokens.push_back({token_type::logical_or, "||"});
            i += 2;
            continue;
        }

        if (c == '=' && i + 1 < len && input[i + 1] == '=') {
            tokens.push_back({token_type::op, "=="});
            i += 2;
            continue;
        }

        if (c == '!' && i + 1 < len && input[i + 1] == '=') {
            tokens.push_back({token_type::op, "!="});
            i += 2;
            continue;
        }

        if (c == '>' && i + 1 < len && input[i + 1] == '=') {
            tokens.push_back({token_type::op, ">="});
            i += 2;
            continue;
        }

        if (c == '<' && i + 1 < len && input[i + 1] == '=') {
            tokens.push_back({token_type::op, "<="});
            i += 2;
            continue;
        }

        if (c == '>') {
            tokens.push_back({token_type::op, ">"});
            ++i;
            continue;
        }

        if (c == '<') {
            tokens.push_back({token_type::op, "<"});
            ++i;
            continue;
        }

        if (c == '"') {
            ++i;
            std::string val;
            while (i < len && input[i] != '"') {
                val += input[i];
                ++i;
            }
            if (i < len) ++i;
            tokens.push_back({token_type::value, val});
            continue;
        }

        if (std::isdigit(static_cast<unsigned char>(c))) {
            std::string val;
            while (i < len && std::isdigit(static_cast<unsigned char>(input[i]))) {
                val += input[i];
                ++i;
            }
            tokens.push_back({token_type::value, val});
            continue;
        }

        if (is_ident_start(c)) {
            std::string ident;
            while (i < len && is_ident_char(input[i])) {
                ident += input[i];
                ++i;
            }
            std::string lower = to_lower(ident);
            if (lower == "and") {
                tokens.push_back({token_type::logical_and, "&&"});
            } else if (lower == "or") {
                tokens.push_back({token_type::logical_or, "||"});
            } else if (lower == "not") {
                tokens.push_back({token_type::logical_not, "!"});
            } else if (lower == "contains") {
                tokens.push_back({token_type::op, "contains"});
            } else if (lower == "true" || lower == "false" ||
                       lower == "inbound" || lower == "outbound") {
                tokens.push_back({token_type::value, lower});
            } else {
                tokens.push_back({token_type::field, ident});
            }
            continue;
        }

        ++i;
    }

    tokens.push_back({token_type::eof, ""});
    return tokens;
}

struct ast_node_t {
    virtual ~ast_node_t() = default;
    virtual bool evaluate(const packet_fields_t& pkt) const = 0;
};

struct comparison_node_t : ast_node_t {
    std::string field;
    std::string op;
    std::string value;

    comparison_node_t(std::string f, std::string o, std::string v)
        : field(std::move(f)), op(std::move(o)), value(std::move(v)) {}

    bool evaluate(const packet_fields_t& pkt) const override {
        std::string field_lower = to_lower(field);

        if (field_lower == "tcp.port") {
            return eval_numeric(pkt.src_port, op, value) ||
                   eval_numeric(pkt.dst_port, op, value);
        }
        if (field_lower == "tcp.src_port" || field_lower == "src_port" || field_lower == "sport") {
            return eval_numeric(pkt.src_port, op, value);
        }
        if (field_lower == "tcp.dst_port" || field_lower == "dst_port" || field_lower == "dport") {
            return eval_numeric(pkt.dst_port, op, value);
        }
        if (field_lower == "ip.src" || field_lower == "src_ip") {
            return eval_string(pkt.src_ip, op, value);
        }
        if (field_lower == "ip.dst" || field_lower == "dst_ip") {
            return eval_string(pkt.dst_ip, op, value);
        }
        if (field_lower == "http.method") {
            return eval_string(pkt.http_method, op, value);
        }
        if (field_lower == "http.status") {
            return eval_numeric(pkt.http_status, op, value);
        }
        if (field_lower == "dns.query") {
            return eval_string(pkt.dns_query, op, value);
        }
        if (field_lower == "tcp.len" || field_lower == "payload.size" || field_lower == "len") {
            return eval_numeric(pkt.payload_size, op, value);
        }
        if (field_lower == "pid") {
            return eval_numeric(pkt.pid, op, value);
        }
        if (field_lower == "protocol") {
            bool try_label = eval_string(pkt.protocol_label, op, value);
            if (try_label) return true;
            return eval_numeric(pkt.protocol, op, value);
        }
        if (field_lower == "direction") {
            std::string dir_str = pkt.direction == 0 ? "inbound" : "outbound";
            bool try_str = eval_string(dir_str, op, value);
            if (try_str) return true;
            return eval_numeric(pkt.direction, op, value);
        }
        if (field_lower == "host") {
            return eval_string(pkt.host, op, value);
        }
        if (field_lower == "summary") {
            return eval_string(pkt.summary, op, value);
        }

        return false;
    }

    static bool try_parse_int64(const std::string& s, int64_t& out) {
        if (s.empty()) return false;
        char* end = nullptr;
        long long val = std::strtoll(s.c_str(), &end, 10);
        if (end == s.c_str() + s.size()) {
            out = static_cast<int64_t>(val);
            return true;
        }
        return false;
    }

    static bool eval_numeric(int64_t field_val, const std::string& oper, const std::string& val_str) {
        int64_t rhs = 0;
        if (!try_parse_int64(val_str, rhs)) return false;
        if (oper == "==") return field_val == rhs;
        if (oper == "!=") return field_val != rhs;
        if (oper == ">")  return field_val > rhs;
        if (oper == "<")  return field_val < rhs;
        if (oper == ">=") return field_val >= rhs;
        if (oper == "<=") return field_val <= rhs;
        return false;
    }

    static bool contains_ci(const std::string& haystack, const std::string& needle) {
        if (needle.empty()) return true;
        if (haystack.size() < needle.size()) return false;
        std::string h = to_lower(haystack);
        std::string n = to_lower(needle);
        return h.find(n) != std::string::npos;
    }

    static bool eval_string(const std::string& field_val, const std::string& oper, const std::string& val_str) {
        if (oper == "contains") {
            return contains_ci(field_val, val_str);
        }
        std::string lhs = to_lower(field_val);
        std::string rhs = to_lower(val_str);
        if (oper == "==") return lhs == rhs;
        if (oper == "!=") return lhs != rhs;
        if (oper == ">")  return lhs > rhs;
        if (oper == "<")  return lhs < rhs;
        if (oper == ">=") return lhs >= rhs;
        if (oper == "<=") return lhs <= rhs;
        return false;
    }
};

struct and_node_t : ast_node_t {
    std::unique_ptr<ast_node_t> left;
    std::unique_ptr<ast_node_t> right;

    and_node_t(std::unique_ptr<ast_node_t> l, std::unique_ptr<ast_node_t> r)
        : left(std::move(l)), right(std::move(r)) {}

    bool evaluate(const packet_fields_t& pkt) const override {
        return left->evaluate(pkt) && right->evaluate(pkt);
    }
};

struct or_node_t : ast_node_t {
    std::unique_ptr<ast_node_t> left;
    std::unique_ptr<ast_node_t> right;

    or_node_t(std::unique_ptr<ast_node_t> l, std::unique_ptr<ast_node_t> r)
        : left(std::move(l)), right(std::move(r)) {}

    bool evaluate(const packet_fields_t& pkt) const override {
        return left->evaluate(pkt) || right->evaluate(pkt);
    }
};

struct not_node_t : ast_node_t {
    std::unique_ptr<ast_node_t> child;

    not_node_t(std::unique_ptr<ast_node_t> c)
        : child(std::move(c)) {}

    bool evaluate(const packet_fields_t& pkt) const override {
        return !child->evaluate(pkt);
    }
};

struct parser_state_t {
    const std::vector<token_t>* tokens = nullptr;
    size_t pos = 0;
    std::string error;
    bool has_error = false;

    const token_t& current() const {
        return (*tokens)[pos];
    }

    const token_t& advance() {
        const token_t& t = (*tokens)[pos];
        if (pos + 1 < tokens->size()) ++pos;
        return t;
    }

    bool expect(token_type type) {
        if (current().type != type) {
            has_error = true;
            error = "unexpected token: " + current().value;
            return false;
        }
        advance();
        return true;
    }

    std::unique_ptr<ast_node_t> parse_expression() {
        return parse_or();
    }

    std::unique_ptr<ast_node_t> parse_or() {
        auto left = parse_and();
        if (!left) return nullptr;
        while (current().type == token_type::logical_or) {
            advance();
            auto right = parse_and();
            if (!right) return nullptr;
            left = std::make_unique<or_node_t>(std::move(left), std::move(right));
        }
        return left;
    }

    std::unique_ptr<ast_node_t> parse_and() {
        auto left = parse_not();
        if (!left) return nullptr;
        while (current().type == token_type::logical_and) {
            advance();
            auto right = parse_not();
            if (!right) return nullptr;
            left = std::make_unique<and_node_t>(std::move(left), std::move(right));
        }
        return left;
    }

    std::unique_ptr<ast_node_t> parse_not() {
        if (current().type == token_type::logical_not) {
            advance();
            auto child = parse_not();
            if (!child) return nullptr;
            return std::make_unique<not_node_t>(std::move(child));
        }
        return parse_primary();
    }

    std::unique_ptr<ast_node_t> parse_primary() {
        if (current().type == token_type::lparen) {
            advance();
            auto expr = parse_expression();
            if (!expr) return nullptr;
            if (!expect(token_type::rparen)) return nullptr;
            return expr;
        }
        return parse_comparison();
    }

    std::unique_ptr<ast_node_t> parse_comparison() {
        if (current().type != token_type::field) {
            has_error = true;
            error = "expected field name, got: " + current().value;
            return nullptr;
        }
        std::string field = advance().value;

        if (current().type != token_type::op) {
            has_error = true;
            error = "expected operator after field '" + field + "'";
            return nullptr;
        }
        std::string op = advance().value;

        if (current().type != token_type::value) {
            has_error = true;
            error = "expected value after operator '" + op + "'";
            return nullptr;
        }
        std::string val = advance().value;

        return std::make_unique<comparison_node_t>(std::move(field), std::move(op), std::move(val));
    }
};

inline std::unique_ptr<ast_node_t> parse(const std::vector<token_t>& tokens) {
    parser_state_t state;
    state.tokens = &tokens;
    state.pos = 0;
    auto root = state.parse_expression();
    if (state.has_error) return nullptr;
    return root;
}

struct compiled_filter_t {
    std::unique_ptr<ast_node_t> root;
    std::string error;
    bool valid = false;

    bool matches(const packet_fields_t& pkt) const {
        if (!valid || !root) return true;
        return root->evaluate(pkt);
    }
};

inline compiled_filter_t compile(const std::string& expression) {
    compiled_filter_t result;

    std::string trimmed = expression;
    while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.front())))
        trimmed.erase(trimmed.begin());
    while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.back())))
        trimmed.pop_back();

    if (trimmed.empty()) {
        result.valid = true;
        return result;
    }

    auto tokens = tokenize(trimmed);

    parser_state_t state;
    state.tokens = &tokens;
    state.pos = 0;
    result.root = state.parse_expression();

    if (state.has_error) {
        result.error = state.error;
        result.valid = false;
        result.root.reset();
        return result;
    }

    if (state.current().type != token_type::eof) {
        result.error = "unexpected token at end: " + state.current().value;
        result.valid = false;
        result.root.reset();
        return result;
    }

    result.valid = true;
    return result;
}

inline bool validate(const std::string& expression, std::string& error) {
    auto result = compile(expression);
    if (!result.valid) {
        error = result.error;
        return false;
    }
    return true;
}

}
