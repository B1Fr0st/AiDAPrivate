#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <cctype>
#include <cstring>

namespace expression_eval {

using read_memory_fn_t = std::function<bool(uint64_t addr, size_t size, void* out)>;

struct eval_result_t {
	bool     ok = false;
	uint64_t value = 0;
	std::string error;
};

struct context_t {
	uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
	uint64_t rsi = 0, rdi = 0, rbp = 0, rsp = 0;
	uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;
	uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
	uint64_t rip = 0, rflags = 0;
	read_memory_fn_t read_mem;
};

namespace detail {

enum class token_type_t {
	number,
	ident,
	lbracket,
	rbracket,
	lparen,
	rparen,
	op_add,
	op_sub,
	op_mul,
	op_div,
	op_mod,
	op_and,
	op_or,
	op_xor,
	op_shl,
	op_shr,
	op_not,
	op_logical_and,
	op_logical_or,
	op_logical_not,
	op_eq,
	op_ne,
	op_lt,
	op_gt,
	op_le,
	op_ge,
	op_tilde,
	end_of_input,
	error,
};

struct token_t {
	token_type_t type = token_type_t::end_of_input;
	uint64_t     num_val = 0;
	std::string  str_val;
};

class lexer_t {
	const char* p_;
	const char* end_;
public:
	lexer_t(const char* src, size_t len) : p_(src), end_(src + len) {}

	void skip_ws() {
		while (p_ < end_ && (*p_ == ' ' || *p_ == '\t')) ++p_;
	}

	token_t next() {
		skip_ws();
		if (p_ >= end_) return {token_type_t::end_of_input};

		char c = *p_;

		if (c == '0' && (p_ + 1) < end_ && (p_[1] == 'x' || p_[1] == 'X')) {
			p_ += 2;
			uint64_t val = 0;
			bool any = false;
			while (p_ < end_ && is_hex_char(*p_)) {
				val = (val << 4) | hex_digit(*p_);
				++p_;
				any = true;
			}
			if (!any) return {token_type_t::error, 0, "invalid hex literal"};
			return {token_type_t::number, val};
		}

		if (c >= '0' && c <= '9') {
			uint64_t val = 0;
			while (p_ < end_ && *p_ >= '0' && *p_ <= '9') {
				val = val * 10 + static_cast<uint64_t>(*p_ - '0');
				++p_;
			}
			if (p_ < end_ && (*p_ == 'h' || *p_ == 'H')) {
				++p_;
				return {token_type_t::number, val};
			}
			return {token_type_t::number, val};
		}

		if (is_ident_start(c)) {
			const char* start = p_;
			while (p_ < end_ && is_ident_char(*p_)) ++p_;
			std::string ident(start, p_);
			return {token_type_t::ident, 0, ident};
		}

		++p_;
		switch (c) {
			case '[': return {token_type_t::lbracket};
			case ']': return {token_type_t::rbracket};
			case '(': return {token_type_t::lparen};
			case ')': return {token_type_t::rparen};
			case '+': return {token_type_t::op_add};
			case '-': return {token_type_t::op_sub};
			case '*': return {token_type_t::op_mul};
			case '/': return {token_type_t::op_div};
			case '%': return {token_type_t::op_mod};
			case '^': return {token_type_t::op_xor};
			case '~': return {token_type_t::op_tilde};
			case '&':
				if (p_ < end_ && *p_ == '&') { ++p_; return {token_type_t::op_logical_and}; }
				return {token_type_t::op_and};
			case '|':
				if (p_ < end_ && *p_ == '|') { ++p_; return {token_type_t::op_logical_or}; }
				return {token_type_t::op_or};
			case '!':
				if (p_ < end_ && *p_ == '=') { ++p_; return {token_type_t::op_ne}; }
				return {token_type_t::op_logical_not};
			case '=':
				if (p_ < end_ && *p_ == '=') { ++p_; return {token_type_t::op_eq}; }
				return {token_type_t::error, 0, "expected '=='"};
			case '<':
				if (p_ < end_ && *p_ == '=') { ++p_; return {token_type_t::op_le}; }
				if (p_ < end_ && *p_ == '<') { ++p_; return {token_type_t::op_shl}; }
				return {token_type_t::op_lt};
			case '>':
				if (p_ < end_ && *p_ == '=') { ++p_; return {token_type_t::op_ge}; }
				if (p_ < end_ && *p_ == '>') { ++p_; return {token_type_t::op_shr}; }
				return {token_type_t::op_gt};
			default:
				return {token_type_t::error, 0, std::string("unexpected char '") + c + "'"};
		}
	}

private:
	static bool is_hex_char(char c) {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
	}
	static uint64_t hex_digit(char c) {
		if (c >= '0' && c <= '9') return static_cast<uint64_t>(c - '0');
		if (c >= 'a' && c <= 'f') return static_cast<uint64_t>(c - 'a' + 10);
		return static_cast<uint64_t>(c - 'A' + 10);
	}
	static bool is_ident_start(char c) {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
	}
	static bool is_ident_char(char c) {
		return is_ident_start(c) || (c >= '0' && c <= '9');
	}
};

class parser_t {
	std::vector<token_t> tokens_;
	size_t               pos_ = 0;
	const context_t*     ctx_ = nullptr;
	std::string          error_;

public:
	parser_t(const std::string& expr, const context_t* ctx) : ctx_(ctx) {
		lexer_t lex(expr.c_str(), expr.size());
		for (;;) {
			auto tok = lex.next();
			if (tok.type == token_type_t::error) {
				error_ = tok.str_val;
				return;
			}
			tokens_.push_back(tok);
			if (tok.type == token_type_t::end_of_input) break;
		}
	}

	eval_result_t parse() {
		if (!error_.empty()) return {false, 0, error_};
		auto r = parse_logical_or();
		if (!r.ok) return r;
		if (peek().type != token_type_t::end_of_input) {
			return {false, 0, "unexpected token at end"};
		}
		return r;
	}

private:
	const token_t& peek() const { return tokens_[pos_]; }
	token_t advance() { return tokens_[pos_++]; }
	bool match(token_type_t t) {
		if (peek().type == t) { advance(); return true; }
		return false;
	}

	eval_result_t parse_logical_or() {
		auto left = parse_logical_and();
		if (!left.ok) return left;
		while (peek().type == token_type_t::op_logical_or) {
			advance();
			auto right = parse_logical_and();
			if (!right.ok) return right;
			left.value = (left.value || right.value) ? 1 : 0;
		}
		return left;
	}

	eval_result_t parse_logical_and() {
		auto left = parse_bitwise_or();
		if (!left.ok) return left;
		while (peek().type == token_type_t::op_logical_and) {
			advance();
			auto right = parse_bitwise_or();
			if (!right.ok) return right;
			left.value = (left.value && right.value) ? 1 : 0;
		}
		return left;
	}

	eval_result_t parse_bitwise_or() {
		auto left = parse_bitwise_xor();
		if (!left.ok) return left;
		while (peek().type == token_type_t::op_or) {
			advance();
			auto right = parse_bitwise_xor();
			if (!right.ok) return right;
			left.value = left.value | right.value;
		}
		return left;
	}

	eval_result_t parse_bitwise_xor() {
		auto left = parse_bitwise_and();
		if (!left.ok) return left;
		while (peek().type == token_type_t::op_xor) {
			advance();
			auto right = parse_bitwise_and();
			if (!right.ok) return right;
			left.value = left.value ^ right.value;
		}
		return left;
	}

	eval_result_t parse_bitwise_and() {
		auto left = parse_equality();
		if (!left.ok) return left;
		while (peek().type == token_type_t::op_and) {
			advance();
			auto right = parse_equality();
			if (!right.ok) return right;
			left.value = left.value & right.value;
		}
		return left;
	}

	eval_result_t parse_equality() {
		auto left = parse_comparison();
		if (!left.ok) return left;
		while (peek().type == token_type_t::op_eq || peek().type == token_type_t::op_ne) {
			auto op = advance().type;
			auto right = parse_comparison();
			if (!right.ok) return right;
			if (op == token_type_t::op_eq)
				left.value = (left.value == right.value) ? 1 : 0;
			else
				left.value = (left.value != right.value) ? 1 : 0;
		}
		return left;
	}

	eval_result_t parse_comparison() {
		auto left = parse_shift();
		if (!left.ok) return left;
		while (peek().type == token_type_t::op_lt || peek().type == token_type_t::op_gt ||
			   peek().type == token_type_t::op_le || peek().type == token_type_t::op_ge) {
			auto op = advance().type;
			auto right = parse_shift();
			if (!right.ok) return right;
			switch (op) {
				case token_type_t::op_lt: left.value = (left.value < right.value) ? 1 : 0; break;
				case token_type_t::op_gt: left.value = (left.value > right.value) ? 1 : 0; break;
				case token_type_t::op_le: left.value = (left.value <= right.value) ? 1 : 0; break;
				case token_type_t::op_ge: left.value = (left.value >= right.value) ? 1 : 0; break;
				default: break;
			}
		}
		return left;
	}

	eval_result_t parse_shift() {
		auto left = parse_additive();
		if (!left.ok) return left;
		while (peek().type == token_type_t::op_shl || peek().type == token_type_t::op_shr) {
			auto op = advance().type;
			auto right = parse_additive();
			if (!right.ok) return right;
			if (op == token_type_t::op_shl)
				left.value = (right.value < 64) ? (left.value << right.value) : 0;
			else
				left.value = (right.value < 64) ? (left.value >> right.value) : 0;
		}
		return left;
	}

	eval_result_t parse_additive() {
		auto left = parse_multiplicative();
		if (!left.ok) return left;
		while (peek().type == token_type_t::op_add || peek().type == token_type_t::op_sub) {
			auto op = advance().type;
			auto right = parse_multiplicative();
			if (!right.ok) return right;
			if (op == token_type_t::op_add)
				left.value = left.value + right.value;
			else
				left.value = left.value - right.value;
		}
		return left;
	}

	eval_result_t parse_multiplicative() {
		auto left = parse_unary();
		if (!left.ok) return left;
		while (peek().type == token_type_t::op_mul || peek().type == token_type_t::op_div ||
			   peek().type == token_type_t::op_mod) {
			auto op = advance().type;
			auto right = parse_unary();
			if (!right.ok) return right;
			if (op == token_type_t::op_mul) {
				left.value = left.value * right.value;
			} else if (op == token_type_t::op_div) {
				if (right.value == 0) return {false, 0, "division by zero"};
				left.value = left.value / right.value;
			} else {
				if (right.value == 0) return {false, 0, "modulo by zero"};
				left.value = left.value % right.value;
			}
		}
		return left;
	}

	eval_result_t parse_unary() {
		if (peek().type == token_type_t::op_sub) {
			advance();
			auto r = parse_unary();
			if (!r.ok) return r;
			r.value = static_cast<uint64_t>(-static_cast<int64_t>(r.value));
			return r;
		}
		if (peek().type == token_type_t::op_tilde) {
			advance();
			auto r = parse_unary();
			if (!r.ok) return r;
			r.value = ~r.value;
			return r;
		}
		if (peek().type == token_type_t::op_logical_not) {
			advance();
			auto r = parse_unary();
			if (!r.ok) return r;
			r.value = r.value ? 0 : 1;
			return r;
		}
		return parse_primary();
	}

	eval_result_t parse_primary() {
		if (peek().type == token_type_t::number) {
			auto tok = advance();
			return {true, tok.num_val};
		}

		if (peek().type == token_type_t::ident) {
			auto tok = advance();
			return resolve_register(tok.str_val);
		}

		if (peek().type == token_type_t::lparen) {
			advance();
			auto r = parse_logical_or();
			if (!r.ok) return r;
			if (!match(token_type_t::rparen))
				return {false, 0, "expected ')'"};
			return r;
		}

		if (peek().type == token_type_t::lbracket) {
			advance();
			auto addr_result = parse_logical_or();
			if (!addr_result.ok) return addr_result;
			if (!match(token_type_t::rbracket))
				return {false, 0, "expected ']'"};
			return read_mem_qword(addr_result.value);
		}

		return {false, 0, "unexpected token"};
	}

	eval_result_t resolve_register(const std::string& name) const {
		std::string lower;
		lower.reserve(name.size());
		for (char c : name) lower += static_cast<char>(tolower(static_cast<unsigned char>(c)));

		if (lower == "rax") return {true, ctx_->rax};
		if (lower == "rbx") return {true, ctx_->rbx};
		if (lower == "rcx") return {true, ctx_->rcx};
		if (lower == "rdx") return {true, ctx_->rdx};
		if (lower == "rsi") return {true, ctx_->rsi};
		if (lower == "rdi") return {true, ctx_->rdi};
		if (lower == "rbp") return {true, ctx_->rbp};
		if (lower == "rsp") return {true, ctx_->rsp};
		if (lower == "r8")  return {true, ctx_->r8};
		if (lower == "r9")  return {true, ctx_->r9};
		if (lower == "r10") return {true, ctx_->r10};
		if (lower == "r11") return {true, ctx_->r11};
		if (lower == "r12") return {true, ctx_->r12};
		if (lower == "r13") return {true, ctx_->r13};
		if (lower == "r14") return {true, ctx_->r14};
		if (lower == "r15") return {true, ctx_->r15};
		if (lower == "rip") return {true, ctx_->rip};
		if (lower == "rflags") return {true, ctx_->rflags};

		if (lower == "eax") return {true, ctx_->rax & 0xFFFFFFFF};
		if (lower == "ebx") return {true, ctx_->rbx & 0xFFFFFFFF};
		if (lower == "ecx") return {true, ctx_->rcx & 0xFFFFFFFF};
		if (lower == "edx") return {true, ctx_->rdx & 0xFFFFFFFF};
		if (lower == "esi") return {true, ctx_->rsi & 0xFFFFFFFF};
		if (lower == "edi") return {true, ctx_->rdi & 0xFFFFFFFF};
		if (lower == "ebp") return {true, ctx_->rbp & 0xFFFFFFFF};
		if (lower == "esp") return {true, ctx_->rsp & 0xFFFFFFFF};
		if (lower == "r8d")  return {true, ctx_->r8 & 0xFFFFFFFF};
		if (lower == "r9d")  return {true, ctx_->r9 & 0xFFFFFFFF};
		if (lower == "r10d") return {true, ctx_->r10 & 0xFFFFFFFF};
		if (lower == "r11d") return {true, ctx_->r11 & 0xFFFFFFFF};
		if (lower == "r12d") return {true, ctx_->r12 & 0xFFFFFFFF};
		if (lower == "r13d") return {true, ctx_->r13 & 0xFFFFFFFF};
		if (lower == "r14d") return {true, ctx_->r14 & 0xFFFFFFFF};
		if (lower == "r15d") return {true, ctx_->r15 & 0xFFFFFFFF};

		if (lower == "ax") return {true, ctx_->rax & 0xFFFF};
		if (lower == "bx") return {true, ctx_->rbx & 0xFFFF};
		if (lower == "cx") return {true, ctx_->rcx & 0xFFFF};
		if (lower == "dx") return {true, ctx_->rdx & 0xFFFF};
		if (lower == "si") return {true, ctx_->rsi & 0xFFFF};
		if (lower == "di") return {true, ctx_->rdi & 0xFFFF};
		if (lower == "bp") return {true, ctx_->rbp & 0xFFFF};
		if (lower == "sp") return {true, ctx_->rsp & 0xFFFF};

		if (lower == "al") return {true, ctx_->rax & 0xFF};
		if (lower == "bl") return {true, ctx_->rbx & 0xFF};
		if (lower == "cl") return {true, ctx_->rcx & 0xFF};
		if (lower == "dl") return {true, ctx_->rdx & 0xFF};
		if (lower == "ah") return {true, (ctx_->rax >> 8) & 0xFF};
		if (lower == "bh") return {true, (ctx_->rbx >> 8) & 0xFF};
		if (lower == "ch") return {true, (ctx_->rcx >> 8) & 0xFF};
		if (lower == "dh") return {true, (ctx_->rdx >> 8) & 0xFF};
		if (lower == "sil") return {true, ctx_->rsi & 0xFF};
		if (lower == "dil") return {true, ctx_->rdi & 0xFF};
		if (lower == "bpl") return {true, ctx_->rbp & 0xFF};
		if (lower == "spl") return {true, ctx_->rsp & 0xFF};
		if (lower == "r8b")  return {true, ctx_->r8 & 0xFF};
		if (lower == "r9b")  return {true, ctx_->r9 & 0xFF};
		if (lower == "r10b") return {true, ctx_->r10 & 0xFF};
		if (lower == "r11b") return {true, ctx_->r11 & 0xFF};
		if (lower == "r12b") return {true, ctx_->r12 & 0xFF};
		if (lower == "r13b") return {true, ctx_->r13 & 0xFF};
		if (lower == "r14b") return {true, ctx_->r14 & 0xFF};
		if (lower == "r15b") return {true, ctx_->r15 & 0xFF};

		if (lower == "r8w")  return {true, ctx_->r8 & 0xFFFF};
		if (lower == "r9w")  return {true, ctx_->r9 & 0xFFFF};
		if (lower == "r10w") return {true, ctx_->r10 & 0xFFFF};
		if (lower == "r11w") return {true, ctx_->r11 & 0xFFFF};
		if (lower == "r12w") return {true, ctx_->r12 & 0xFFFF};
		if (lower == "r13w") return {true, ctx_->r13 & 0xFFFF};
		if (lower == "r14w") return {true, ctx_->r14 & 0xFFFF};
		if (lower == "r15w") return {true, ctx_->r15 & 0xFFFF};

		return {false, 0, "unknown register '" + name + "'"};
	}

	eval_result_t read_mem_qword(uint64_t addr) const {
		if (!ctx_->read_mem) return {false, 0, "no memory read function"};
		uint64_t val = 0;
		if (!ctx_->read_mem(addr, 8, &val))
			return {false, 0, "failed to read memory at 0x" + to_hex(addr)};
		return {true, val};
	}

	static std::string to_hex(uint64_t v) {
		char buf[24];
		snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
		return buf;
	}
};

}

inline eval_result_t evaluate(const std::string& expression, const context_t& ctx)
{
	detail::parser_t parser(expression, &ctx);
	return parser.parse();
}

inline std::string format_log_text(const std::string& format, const context_t& ctx)
{
	std::string result;
	result.reserve(format.size() * 2);
	size_t i = 0;
	while (i < format.size()) {
		if (format[i] == '{') {
			size_t close = format.find('}', i + 1);
			if (close == std::string::npos) {
				result += format[i];
				++i;
				continue;
			}
			std::string inner = format.substr(i + 1, close - i - 1);
			auto r = evaluate(inner, ctx);
			if (r.ok) {
				char buf[24];
				snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(r.value));
				result += buf;
			} else {
				result += "?";
			}
			i = close + 1;
		} else {
			result += format[i];
			++i;
		}
	}
	return result;
}

}
