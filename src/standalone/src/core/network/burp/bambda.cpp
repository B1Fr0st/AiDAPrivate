#include "bambda.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace bambda {

namespace {

std::mutex& err_mtx()
{
    static std::mutex m;
    return m;
}

std::string& err_slot()
{
    static std::string e;
    return e;
}

void set_err(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = msg;
}

enum class node_kind_t : int
{
    nk_or = 0,
    nk_and,
    nk_not,
    nk_cmp
};

enum class op_kind_t : int
{
    op_eq = 0,
    op_ne,
    op_lt,
    op_le,
    op_gt,
    op_ge,
    op_contains,
    op_starts_with,
    op_ends_with,
    op_matches,
    op_in
};

enum class value_kind_t : int
{
    vk_string = 0,
    vk_number,
    vk_regex,
    vk_list
};

struct value_t
{
    value_kind_t          kind = value_kind_t::vk_string;
    std::string           str_val;
    int64_t               num_val = 0;
    bool                  regex_case_insensitive = false;
    std::vector<value_t>  list_val;
};

struct ast_node_t
{
    node_kind_t                          kind = node_kind_t::nk_cmp;
    std::vector<std::shared_ptr<ast_node_t>> children;
    std::string                          field_path;
    op_kind_t                            op = op_kind_t::op_eq;
    value_t                              val;
};

struct token_t
{
    enum class kind_t : int
    {
        end = 0,
        ident,
        number,
        string,
        regex,
        l_paren,
        r_paren,
        l_bracket,
        r_bracket,
        comma,
        dot,
        and_op,
        or_op,
        not_op,
        op_eq,
        op_ne,
        op_lt,
        op_le,
        op_gt,
        op_ge,
        kw_contains,
        kw_starts_with,
        kw_ends_with,
        kw_matches,
        kw_in
    };
    kind_t       kind = kind_t::end;
    std::string  text;
    int64_t      num = 0;
    bool         regex_ci = false;
};

class lexer_t
{
public:
    lexer_t(const std::string& src) : src_(src), pos_(0) {}

    bool next(token_t& t, std::string& err_out)
    {
        t = token_t{};
        skip_ws();
        if (pos_ >= src_.size()) { t.kind = token_t::kind_t::end; return true; }
        char c = src_[pos_];

        if (c == '(') { ++pos_; t.kind = token_t::kind_t::l_paren; return true; }
        if (c == ')') { ++pos_; t.kind = token_t::kind_t::r_paren; return true; }
        if (c == '[') { ++pos_; t.kind = token_t::kind_t::l_bracket; return true; }
        if (c == ']') { ++pos_; t.kind = token_t::kind_t::r_bracket; return true; }
        if (c == ',') { ++pos_; t.kind = token_t::kind_t::comma; return true; }
        if (c == '.') { ++pos_; t.kind = token_t::kind_t::dot; return true; }
        if (c == '!') {
            if (pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') {
                pos_ += 2;
                t.kind = token_t::kind_t::op_ne; return true;
            }
            ++pos_;
            t.kind = token_t::kind_t::not_op;
            return true;
        }
        if (c == '=' && pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') {
            pos_ += 2;
            t.kind = token_t::kind_t::op_eq;
            return true;
        }
        if (c == '<') {
            if (pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') { pos_ += 2; t.kind = token_t::kind_t::op_le; return true; }
            ++pos_;
            t.kind = token_t::kind_t::op_lt;
            return true;
        }
        if (c == '>') {
            if (pos_ + 1 < src_.size() && src_[pos_ + 1] == '=') { pos_ += 2; t.kind = token_t::kind_t::op_ge; return true; }
            ++pos_;
            t.kind = token_t::kind_t::op_gt;
            return true;
        }
        if (c == '&') {
            if (pos_ + 1 < src_.size() && src_[pos_ + 1] == '&') { pos_ += 2; t.kind = token_t::kind_t::and_op; return true; }
            err_out = "expected '&&' got '&'";
            return false;
        }
        if (c == '|') {
            if (pos_ + 1 < src_.size() && src_[pos_ + 1] == '|') { pos_ += 2; t.kind = token_t::kind_t::or_op; return true; }
            err_out = "expected '||' got '|'";
            return false;
        }
        if (c == '"' || c == '\'') {
            return read_string(c, t, err_out);
        }
        if (c == '/') {
            return read_regex(t, err_out);
        }
        if (c >= '0' && c <= '9') {
            return read_number(t, err_out);
        }
        if (c == '-' && pos_ + 1 < src_.size() && src_[pos_ + 1] >= '0' && src_[pos_ + 1] <= '9') {
            return read_number(t, err_out);
        }
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
            return read_ident_or_kw(t, err_out);
        }
        err_out = std::string("unexpected character '") + c + "'";
        return false;
    }

    size_t pos() const { return pos_; }

private:
    void skip_ws()
    {
        while (pos_ < src_.size()) {
            char c = src_[pos_];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { ++pos_; continue; }
            break;
        }
    }

    bool read_string(char delim, token_t& t, std::string& err_out)
    {
        ++pos_;
        std::string out;
        while (pos_ < src_.size()) {
            char c = src_[pos_];
            if (c == '\\' && pos_ + 1 < src_.size()) {
                char n = src_[pos_ + 1];
                switch (n) {
                    case 'n': out.push_back('\n'); break;
                    case 't': out.push_back('\t'); break;
                    case 'r': out.push_back('\r'); break;
                    case '\\': out.push_back('\\'); break;
                    case '"': out.push_back('"'); break;
                    case '\'': out.push_back('\''); break;
                    case '/': out.push_back('/'); break;
                    default: out.push_back(n); break;
                }
                pos_ += 2;
                continue;
            }
            if (c == delim) { ++pos_; t.kind = token_t::kind_t::string; t.text = std::move(out); return true; }
            out.push_back(c);
            ++pos_;
        }
        err_out = "unterminated string literal";
        return false;
    }

    bool read_regex(token_t& t, std::string& err_out)
    {
        ++pos_;
        std::string out;
        while (pos_ < src_.size()) {
            char c = src_[pos_];
            if (c == '\\' && pos_ + 1 < src_.size()) {
                out.push_back(c);
                out.push_back(src_[pos_ + 1]);
                pos_ += 2;
                continue;
            }
            if (c == '/') {
                ++pos_;
                if (pos_ < src_.size() && (src_[pos_] == 'i' || src_[pos_] == 'I')) {
                    t.regex_ci = true;
                    ++pos_;
                }
                t.kind = token_t::kind_t::regex;
                t.text = std::move(out);
                return true;
            }
            out.push_back(c);
            ++pos_;
        }
        err_out = "unterminated regex literal";
        return false;
    }

    bool read_number(token_t& t, std::string& err_out)
    {
        bool negative = false;
        if (src_[pos_] == '-') { negative = true; ++pos_; }
        int64_t v = 0;
        size_t start = pos_;
        while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') {
            int64_t d = static_cast<int64_t>(src_[pos_] - '0');
            if (v > (INT64_MAX - d) / 10) { err_out = "number overflow"; return false; }
            v = v * 10 + d;
            ++pos_;
        }
        if (pos_ == start) { err_out = "expected digit"; return false; }
        if (negative) v = -v;
        t.kind = token_t::kind_t::number;
        t.num = v;
        return true;
    }

    bool read_ident_or_kw(token_t& t, std::string& err_out)
    {
        (void)err_out;
        std::string out;
        while (pos_ < src_.size()) {
            char c = src_[pos_];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
                out.push_back(c);
                ++pos_;
                continue;
            }
            break;
        }
        if (out == "contains") { t.kind = token_t::kind_t::kw_contains; return true; }
        if (out == "starts_with") { t.kind = token_t::kind_t::kw_starts_with; return true; }
        if (out == "ends_with") { t.kind = token_t::kind_t::kw_ends_with; return true; }
        if (out == "matches") { t.kind = token_t::kind_t::kw_matches; return true; }
        if (out == "in") { t.kind = token_t::kind_t::kw_in; return true; }
        if (out == "true" || out == "false") {
            t.kind = token_t::kind_t::number;
            t.num = (out == "true") ? 1 : 0;
            return true;
        }
        t.kind = token_t::kind_t::ident;
        t.text = std::move(out);
        return true;
    }

    const std::string& src_;
    size_t             pos_;
};

class parser_t
{
public:
    parser_t(const std::string& src) : lex_(src), failed_(false) {}

    bool parse(std::shared_ptr<ast_node_t>& out, std::string& err_out)
    {
        if (!advance(err_out)) return false;
        auto node = parse_or(err_out);
        if (!node) { failed_ = true; return false; }
        if (cur_.kind != token_t::kind_t::end) {
            err_out = "unexpected trailing tokens";
            return false;
        }
        out = node;
        return true;
    }

private:
    bool advance(std::string& err_out)
    {
        return lex_.next(cur_, err_out);
    }

    std::shared_ptr<ast_node_t> parse_or(std::string& err_out)
    {
        auto left = parse_and(err_out);
        if (!left) return nullptr;
        while (cur_.kind == token_t::kind_t::or_op) {
            if (!advance(err_out)) return nullptr;
            auto right = parse_and(err_out);
            if (!right) return nullptr;
            auto node = std::make_shared<ast_node_t>();
            node->kind = node_kind_t::nk_or;
            node->children.push_back(left);
            node->children.push_back(right);
            left = node;
        }
        return left;
    }

    std::shared_ptr<ast_node_t> parse_and(std::string& err_out)
    {
        auto left = parse_not(err_out);
        if (!left) return nullptr;
        while (cur_.kind == token_t::kind_t::and_op) {
            if (!advance(err_out)) return nullptr;
            auto right = parse_not(err_out);
            if (!right) return nullptr;
            auto node = std::make_shared<ast_node_t>();
            node->kind = node_kind_t::nk_and;
            node->children.push_back(left);
            node->children.push_back(right);
            left = node;
        }
        return left;
    }

    std::shared_ptr<ast_node_t> parse_not(std::string& err_out)
    {
        if (cur_.kind == token_t::kind_t::not_op) {
            if (!advance(err_out)) return nullptr;
            auto child = parse_not(err_out);
            if (!child) return nullptr;
            auto node = std::make_shared<ast_node_t>();
            node->kind = node_kind_t::nk_not;
            node->children.push_back(child);
            return node;
        }
        return parse_atom(err_out);
    }

    std::shared_ptr<ast_node_t> parse_atom(std::string& err_out)
    {
        if (cur_.kind == token_t::kind_t::l_paren) {
            if (!advance(err_out)) return nullptr;
            auto node = parse_or(err_out);
            if (!node) return nullptr;
            if (cur_.kind != token_t::kind_t::r_paren) {
                err_out = "expected ')'";
                return nullptr;
            }
            if (!advance(err_out)) return nullptr;
            return node;
        }
        return parse_comparison(err_out);
    }

    std::shared_ptr<ast_node_t> parse_comparison(std::string& err_out)
    {
        if (cur_.kind != token_t::kind_t::ident) {
            err_out = "expected field identifier";
            return nullptr;
        }
        std::string path = cur_.text;
        if (!advance(err_out)) return nullptr;
        while (cur_.kind == token_t::kind_t::dot) {
            if (!advance(err_out)) return nullptr;
            if (cur_.kind != token_t::kind_t::ident) {
                err_out = "expected identifier after '.'";
                return nullptr;
            }
            path += '.';
            path += cur_.text;
            if (!advance(err_out)) return nullptr;
        }

        auto node = std::make_shared<ast_node_t>();
        node->kind = node_kind_t::nk_cmp;
        node->field_path = path;

        switch (cur_.kind) {
            case token_t::kind_t::op_eq:           node->op = op_kind_t::op_eq; break;
            case token_t::kind_t::op_ne:           node->op = op_kind_t::op_ne; break;
            case token_t::kind_t::op_lt:           node->op = op_kind_t::op_lt; break;
            case token_t::kind_t::op_le:           node->op = op_kind_t::op_le; break;
            case token_t::kind_t::op_gt:           node->op = op_kind_t::op_gt; break;
            case token_t::kind_t::op_ge:           node->op = op_kind_t::op_ge; break;
            case token_t::kind_t::kw_contains:     node->op = op_kind_t::op_contains; break;
            case token_t::kind_t::kw_starts_with:  node->op = op_kind_t::op_starts_with; break;
            case token_t::kind_t::kw_ends_with:    node->op = op_kind_t::op_ends_with; break;
            case token_t::kind_t::kw_matches:      node->op = op_kind_t::op_matches; break;
            case token_t::kind_t::kw_in:           node->op = op_kind_t::op_in; break;
            default:
                err_out = "expected comparison operator";
                return nullptr;
        }
        if (!advance(err_out)) return nullptr;

        if (!parse_value(node->val, err_out)) return nullptr;
        return node;
    }

    bool parse_value(value_t& out, std::string& err_out)
    {
        switch (cur_.kind) {
            case token_t::kind_t::string:
                out.kind = value_kind_t::vk_string;
                out.str_val = cur_.text;
                return advance(err_out);
            case token_t::kind_t::number:
                out.kind = value_kind_t::vk_number;
                out.num_val = cur_.num;
                return advance(err_out);
            case token_t::kind_t::regex:
                out.kind = value_kind_t::vk_regex;
                out.str_val = cur_.text;
                out.regex_case_insensitive = cur_.regex_ci;
                return advance(err_out);
            case token_t::kind_t::l_bracket: {
                if (!advance(err_out)) return false;
                out.kind = value_kind_t::vk_list;
                if (cur_.kind == token_t::kind_t::r_bracket) {
                    return advance(err_out);
                }
                while (true) {
                    value_t inner;
                    if (!parse_value(inner, err_out)) return false;
                    out.list_val.push_back(inner);
                    if (cur_.kind == token_t::kind_t::comma) {
                        if (!advance(err_out)) return false;
                        continue;
                    }
                    if (cur_.kind == token_t::kind_t::r_bracket) {
                        return advance(err_out);
                    }
                    err_out = "expected ',' or ']' in list";
                    return false;
                }
            }
            default:
                err_out = "expected value (string, number, regex, list)";
                return false;
        }
    }

    lexer_t            lex_;
    token_t            cur_;
    bool               failed_;
};

bool to_number(const std::string& s, int64_t& out)
{
    if (s.empty()) return false;
    size_t i = 0;
    bool neg = false;
    if (s[0] == '-') { neg = true; i = 1; }
    int64_t v = 0;
    bool any = false;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        v = v * 10 + (s[i] - '0');
        ++i; any = true;
    }
    if (!any) return false;
    if (i != s.size()) return false;
    out = neg ? -v : v;
    return true;
}

std::string str_lower(const std::string& s)
{
    std::string r;
    r.reserve(s.size());
    for (char c : s) r.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return r;
}

bool value_equal_string(const value_t& v, const std::string& s)
{
    if (v.kind == value_kind_t::vk_string) return v.str_val == s;
    if (v.kind == value_kind_t::vk_number) {
        int64_t n;
        if (to_number(s, n)) return n == v.num_val;
        return false;
    }
    return false;
}

bool value_equal_number(const value_t& v, int64_t n)
{
    if (v.kind == value_kind_t::vk_number) return v.num_val == n;
    if (v.kind == value_kind_t::vk_string) {
        int64_t m;
        if (to_number(v.str_val, m)) return m == n;
        return false;
    }
    return false;
}

bool eval_cmp(const ast_node_t& node, const row_view_t& row)
{
    if (node.op == op_kind_t::op_in) {
        if (node.val.kind != value_kind_t::vk_list) return false;
        std::optional<std::string> sval = row.get_string ? row.get_string(node.field_path) : std::nullopt;
        std::optional<int64_t>     nval = row.get_number ? row.get_number(node.field_path) : std::nullopt;
        for (const auto& item : node.val.list_val) {
            if (item.kind == value_kind_t::vk_string && sval.has_value() && *sval == item.str_val) return true;
            if (item.kind == value_kind_t::vk_number && nval.has_value() && *nval == item.num_val) return true;
            if (item.kind == value_kind_t::vk_string && nval.has_value()) {
                int64_t parsed;
                if (to_number(item.str_val, parsed) && parsed == *nval) return true;
            }
            if (item.kind == value_kind_t::vk_number && sval.has_value()) {
                int64_t parsed;
                if (to_number(*sval, parsed) && parsed == item.num_val) return true;
            }
        }
        return false;
    }

    if (node.op == op_kind_t::op_matches) {
        if (node.val.kind != value_kind_t::vk_regex) return false;
        std::optional<std::string> sval = row.get_string ? row.get_string(node.field_path) : std::nullopt;
        if (!sval.has_value()) return false;
        try {
            auto flags = std::regex::ECMAScript;
            if (node.val.regex_case_insensitive) flags = static_cast<std::regex::flag_type>(flags | std::regex::icase);
            std::regex re(node.val.str_val, flags);
            return std::regex_search(*sval, re);
        } catch (...) {
            return false;
        }
    }

    if (node.op == op_kind_t::op_contains ||
        node.op == op_kind_t::op_starts_with ||
        node.op == op_kind_t::op_ends_with) {
        if (node.val.kind != value_kind_t::vk_string) return false;
        std::optional<std::string> sval = row.get_string ? row.get_string(node.field_path) : std::nullopt;
        if (!sval.has_value()) return false;
        const std::string& haystack = *sval;
        const std::string& needle = node.val.str_val;
        if (needle.empty()) return false;
        if (node.op == op_kind_t::op_contains) return haystack.find(needle) != std::string::npos;
        if (node.op == op_kind_t::op_starts_with) {
            if (haystack.size() < needle.size()) return false;
            return haystack.compare(0, needle.size(), needle) == 0;
        }
        if (node.op == op_kind_t::op_ends_with) {
            if (haystack.size() < needle.size()) return false;
            return haystack.compare(haystack.size() - needle.size(), needle.size(), needle) == 0;
        }
        return false;
    }

    if (node.val.kind == value_kind_t::vk_number) {
        int64_t n;
        std::optional<int64_t> sn = row.get_number ? row.get_number(node.field_path) : std::nullopt;
        if (!sn.has_value()) {
            std::optional<std::string> ss = row.get_string ? row.get_string(node.field_path) : std::nullopt;
            if (ss.has_value() && to_number(*ss, n)) sn = n;
        }
        if (!sn.has_value()) return false;
        int64_t lhs = *sn;
        int64_t rhs = node.val.num_val;
        switch (node.op) {
            case op_kind_t::op_eq: return lhs == rhs;
            case op_kind_t::op_ne: return lhs != rhs;
            case op_kind_t::op_lt: return lhs <  rhs;
            case op_kind_t::op_le: return lhs <= rhs;
            case op_kind_t::op_gt: return lhs >  rhs;
            case op_kind_t::op_ge: return lhs >= rhs;
            default: return false;
        }
    }

    if (node.val.kind == value_kind_t::vk_string) {
        std::optional<std::string> ss = row.get_string ? row.get_string(node.field_path) : std::nullopt;
        if (!ss.has_value()) {
            std::optional<int64_t> sn = row.get_number ? row.get_number(node.field_path) : std::nullopt;
            if (sn.has_value()) ss = std::to_string(*sn);
        }
        if (!ss.has_value()) return false;
        const std::string& lhs = *ss;
        const std::string& rhs = node.val.str_val;
        switch (node.op) {
            case op_kind_t::op_eq: return lhs == rhs;
            case op_kind_t::op_ne: return lhs != rhs;
            case op_kind_t::op_lt: return lhs <  rhs;
            case op_kind_t::op_le: return lhs <= rhs;
            case op_kind_t::op_gt: return lhs >  rhs;
            case op_kind_t::op_ge: return lhs >= rhs;
            default: return false;
        }
    }

    return false;
}

bool eval_node(const ast_node_t& node, const row_view_t& row)
{
    switch (node.kind) {
        case node_kind_t::nk_or:
            for (const auto& c : node.children) if (c && eval_node(*c, row)) return true;
            return false;
        case node_kind_t::nk_and:
            for (const auto& c : node.children) if (!c || !eval_node(*c, row)) return false;
            return true;
        case node_kind_t::nk_not:
            if (node.children.empty() || !node.children[0]) return false;
            return !eval_node(*node.children[0], row);
        case node_kind_t::nk_cmp:
            return eval_cmp(node, row);
    }
    return false;
}

std::string to_lower_owned(const std::string& s)
{
    std::string r;
    r.reserve(s.size());
    for (char c : s) r.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return r;
}

std::string header_value(const std::vector<std::pair<std::string, std::string>>& h, const std::string& name)
{
    std::string lc = to_lower_owned(name);
    for (const auto& p : h) {
        if (to_lower_owned(p.first) == lc) return p.second;
    }
    return std::string();
}

}

bambda_program_t compile(const std::string& source)
{
    bambda_program_t prog;
    prog.source = source;
    prog.valid = false;
    if (source.empty()) {
        prog.error = "empty";
        set_err(prog.error);
        return prog;
    }
    parser_t p(source);
    std::shared_ptr<ast_node_t> root;
    std::string err;
    if (!p.parse(root, err) || !root) {
        prog.error = err.empty() ? std::string("parse_failed") : err;
        set_err(prog.error);
        return prog;
    }
    prog.ast = std::static_pointer_cast<void>(root);
    prog.valid = true;
    return prog;
}

bool evaluate(const bambda_program_t& p, const row_view_t& row)
{
    if (!p.valid || !p.ast) return false;
    auto root = std::static_pointer_cast<ast_node_t>(p.ast);
    if (!root) return false;
    return eval_node(*root, row);
}

row_view_t make_provider_for_exchange(const exchange_observed_t& e)
{
    row_view_t v;
    const exchange_observed_t* ep = &e;
    v.get_string = [ep](const std::string& path) -> std::optional<std::string> {
        if (path == "request.method")        return ep->method;
        if (path == "request.host")          return ep->host;
        if (path == "request.scheme")        return ep->scheme;
        if (path == "request.path")          return ep->path;
        if (path == "request.query")         return ep->query;
        if (path == "request.url") {
            std::string u = ep->scheme.empty() ? std::string("http") : ep->scheme;
            u += "://";
            u += ep->host;
            u += ep->path;
            if (!ep->query.empty()) {
                u.push_back('?');
                u.append(ep->query);
            }
            return u;
        }
        if (path == "response.reason")       return ep->reason_phrase;
        if (path == "tls.version")           return ep->tls_version;
        if (path == "tls.alpn")              return ep->alpn;
        if (path == "client.addr")           return ep->client_addr;
        if (path.rfind("request.header.", 0) == 0) {
            return header_value(ep->req_headers, path.substr(15));
        }
        if (path.rfind("response.header.", 0) == 0) {
            return header_value(ep->resp_headers, path.substr(16));
        }
        if (path == "request.body") {
            return std::string(reinterpret_cast<const char*>(ep->req_body.data()), ep->req_body.size());
        }
        if (path == "response.body") {
            return std::string(reinterpret_cast<const char*>(ep->resp_body.data()), ep->resp_body.size());
        }
        return std::nullopt;
    };
    v.get_number = [ep](const std::string& path) -> std::optional<int64_t> {
        if (path == "request.port")      return static_cast<int64_t>(ep->port);
        if (path == "response.status")   return static_cast<int64_t>(ep->status_code);
        if (path == "response.size")     return static_cast<int64_t>(ep->resp_body.size());
        if (path == "request.size")      return static_cast<int64_t>(ep->req_body.size());
        if (path == "latency_ms")        return static_cast<int64_t>(ep->latency_ms);
        if (path == "timestamp_ms")      return static_cast<int64_t>(ep->timestamp_ms);
        if (path == "client.port")       return static_cast<int64_t>(ep->client_port);
        if (path == "is_websocket")      return ep->is_websocket ? 1 : 0;
        if (path == "is_h2")             return ep->is_h2 ? 1 : 0;
        return std::nullopt;
    };
    return v;
}

std::string bambda_help_text()
{
    return std::string(
        "Bambda filter DSL\n"
        "-----------------\n"
        "Grammar: expression with operators && || ! grouped with ().\n"
        "Each comparison: <field> <op> <value>.\n"
        "\n"
        "Fields (string): request.method, request.host, request.scheme, request.path,\n"
        "  request.query, request.url, response.reason, tls.version, tls.alpn,\n"
        "  client.addr, request.header.<name>, response.header.<name>,\n"
        "  request.body, response.body\n"
        "Fields (number): request.port, response.status, response.size, request.size,\n"
        "  latency_ms, timestamp_ms, client.port, is_websocket, is_h2\n"
        "\n"
        "Operators: == != < <= > >= contains starts_with ends_with matches in\n"
        "Values: \"string\" 'string' 123 /regex/ /regex/i [a, b, c]\n"
        "\n"
        "Examples:\n"
        "  response.status >= 400\n"
        "  request.host contains \"api\" && response.status == 500\n"
        "  response.header.Content-Type matches /application/json/i\n"
        "  request.method in [\"POST\", \"PUT\", \"DELETE\"]\n"
    );
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    return err_slot();
}

}
}
}
