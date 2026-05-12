#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <cstring>
#include <cmath>

namespace protobuf_codec {

enum class wire_type_t : uint8_t {
	varint = 0,
	fixed64 = 1,
	length_delimited = 2,
	fixed32 = 5,
};

enum class field_display_t : uint8_t {
	uint_val = 0,
	sint_val,
	int_val,
	bool_val,
	float_val,
	double_val,
	string_val,
	bytes_val,
	nested_message,
	fixed32_val,
	fixed64_val,
	sfixed32_val,
	sfixed64_val,
	enum_val,
};

struct field_t {
	uint32_t field_number = 0;
	wire_type_t wire_type = wire_type_t::varint;
	field_display_t display_type = field_display_t::uint_val;

	uint64_t varint_value = 0;
	uint64_t fixed64_value = 0;
	uint32_t fixed32_value = 0;
	std::vector<uint8_t> bytes_value;
	std::string string_value;

	std::vector<field_t> nested_fields;

	bool is_nested = false;
	int depth = 0;
};

struct grpc_frame_t {
	uint8_t compressed = 0;
	uint32_t length = 0;
	std::vector<uint8_t> data;
};

inline bool read_varint(const uint8_t* data, size_t len, size_t& offset, uint64_t& out) {
	out = 0;
	uint32_t shift = 0;
	while (offset < len) {
		if (shift >= 64) return false;
		uint8_t b = data[offset++];
		out |= static_cast<uint64_t>(b & 0x7F) << shift;
		if ((b & 0x80) == 0) return true;
		shift += 7;
	}
	return false;
}

inline void write_varint(std::vector<uint8_t>& buf, uint64_t value) {
	while (value >= 0x80) {
		buf.push_back(static_cast<uint8_t>((value & 0x7F) | 0x80));
		value >>= 7;
	}
	buf.push_back(static_cast<uint8_t>(value));
}

inline int64_t zigzag_decode(uint64_t n) {
	return static_cast<int64_t>((n >> 1) ^ (~(n & 1) + 1));
}

inline uint64_t zigzag_encode(int64_t n) {
	uint64_t u = static_cast<uint64_t>(n);
	uint64_t sign_mask = static_cast<uint64_t>(0) - (u >> 63);
	return (u << 1) ^ sign_mask;
}

inline bool is_printable_byte(uint8_t b) {
	return (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r';
}

inline std::vector<field_t> decode(const uint8_t* data, size_t len, int depth = 0);

inline bool try_decode_nested(const uint8_t* data, size_t len, std::vector<field_t>& out, int depth) {
	if (len == 0) return false;
	if (depth >= 8) return false;

	size_t offset = 0;
	std::vector<field_t> fields;

	while (offset < len) {
		uint64_t tag = 0;
		size_t saved = offset;
		if (!read_varint(data, len, offset, tag)) return false;

		uint32_t field_number = static_cast<uint32_t>(tag >> 3);
		uint32_t wt = static_cast<uint32_t>(tag & 0x07);

		if (field_number == 0) return false;
		if (wt != 0 && wt != 1 && wt != 2 && wt != 5) return false;

		field_t f;
		f.field_number = field_number;
		f.wire_type = static_cast<wire_type_t>(wt);
		f.depth = depth;

		switch (f.wire_type) {
		case wire_type_t::varint: {
			if (!read_varint(data, len, offset, f.varint_value)) return false;
			f.display_type = field_display_t::uint_val;
			break;
		}
		case wire_type_t::fixed64: {
			if (offset + 8 > len) return false;
			std::memcpy(&f.fixed64_value, data + offset, 8);
			offset += 8;
			f.display_type = field_display_t::fixed64_val;
			break;
		}
		case wire_type_t::length_delimited: {
			uint64_t field_len = 0;
			if (!read_varint(data, len, offset, field_len)) return false;
			if (field_len > len - offset) return false;

			f.bytes_value.assign(data + offset, data + offset + static_cast<size_t>(field_len));
			offset += static_cast<size_t>(field_len);

			std::vector<field_t> nested;
			if (field_len > 0 && try_decode_nested(f.bytes_value.data(), f.bytes_value.size(), nested, depth + 1)) {
				f.nested_fields = std::move(nested);
				f.is_nested = true;
				f.display_type = field_display_t::nested_message;
			} else {
				bool all_printable = true;
				for (auto b : f.bytes_value) {
					if (!is_printable_byte(b)) {
						all_printable = false;
						break;
					}
				}
				if (all_printable && !f.bytes_value.empty()) {
					f.string_value.assign(f.bytes_value.begin(), f.bytes_value.end());
					f.display_type = field_display_t::string_val;
				} else {
					f.display_type = field_display_t::bytes_val;
				}
			}
			break;
		}
		case wire_type_t::fixed32: {
			if (offset + 4 > len) return false;
			std::memcpy(&f.fixed32_value, data + offset, 4);
			offset += 4;
			f.display_type = field_display_t::fixed32_val;
			break;
		}
		default:
			return false;
		}

		fields.push_back(std::move(f));
	}

	if (offset != len) return false;
	if (fields.empty()) return false;

	out = std::move(fields);
	return true;
}

inline std::vector<field_t> decode(const uint8_t* data, size_t len, int depth) {
	std::vector<field_t> result;
	if (!data || len == 0) return result;
	if (depth >= 8) return result;

	size_t offset = 0;
	while (offset < len) {
		uint64_t tag = 0;
		if (!read_varint(data, len, offset, tag)) break;

		uint32_t field_number = static_cast<uint32_t>(tag >> 3);
		uint32_t wt = static_cast<uint32_t>(tag & 0x07);

		if (field_number == 0) break;
		if (wt != 0 && wt != 1 && wt != 2 && wt != 5) break;

		field_t f;
		f.field_number = field_number;
		f.wire_type = static_cast<wire_type_t>(wt);
		f.depth = depth;

		switch (f.wire_type) {
		case wire_type_t::varint: {
			if (!read_varint(data, len, offset, f.varint_value)) { offset = len; break; }
			f.display_type = field_display_t::uint_val;
			break;
		}
		case wire_type_t::fixed64: {
			if (offset + 8 > len) { offset = len; break; }
			std::memcpy(&f.fixed64_value, data + offset, 8);
			offset += 8;
			f.display_type = field_display_t::fixed64_val;
			break;
		}
		case wire_type_t::length_delimited: {
			uint64_t field_len = 0;
			if (!read_varint(data, len, offset, field_len)) { offset = len; break; }
			if (field_len > len - offset) { offset = len; break; }

			f.bytes_value.assign(data + offset, data + offset + static_cast<size_t>(field_len));
			offset += static_cast<size_t>(field_len);

			std::vector<field_t> nested;
			if (field_len > 0 && try_decode_nested(f.bytes_value.data(), f.bytes_value.size(), nested, depth + 1)) {
				f.nested_fields = std::move(nested);
				f.is_nested = true;
				f.display_type = field_display_t::nested_message;
			} else {
				bool all_printable = true;
				for (auto b : f.bytes_value) {
					if (!is_printable_byte(b)) {
						all_printable = false;
						break;
					}
				}
				if (all_printable && !f.bytes_value.empty()) {
					f.string_value.assign(f.bytes_value.begin(), f.bytes_value.end());
					f.display_type = field_display_t::string_val;
				} else {
					f.display_type = field_display_t::bytes_val;
				}
			}
			break;
		}
		case wire_type_t::fixed32: {
			if (offset + 4 > len) { offset = len; break; }
			std::memcpy(&f.fixed32_value, data + offset, 4);
			offset += 4;
			f.display_type = field_display_t::fixed32_val;
			break;
		}
		default:
			offset = len;
			break;
		}

		result.push_back(std::move(f));
	}

	return result;
}

inline std::vector<uint8_t> encode_fields(const std::vector<field_t>& fields);

inline std::vector<uint8_t> encode(const std::vector<field_t>& fields) {
	return encode_fields(fields);
}

inline std::vector<uint8_t> encode_fields(const std::vector<field_t>& fields) {
	std::vector<uint8_t> buf;
	for (const auto& f : fields) {
		uint32_t tag = (f.field_number << 3) | static_cast<uint32_t>(f.wire_type);
		write_varint(buf, tag);

		switch (f.wire_type) {
		case wire_type_t::varint: {
			write_varint(buf, f.varint_value);
			break;
		}
		case wire_type_t::fixed64: {
			uint8_t tmp[8];
			std::memcpy(tmp, &f.fixed64_value, 8);
			buf.insert(buf.end(), tmp, tmp + 8);
			break;
		}
		case wire_type_t::length_delimited: {
			if (f.is_nested && !f.nested_fields.empty()) {
				auto nested_bytes = encode_fields(f.nested_fields);
				write_varint(buf, nested_bytes.size());
				buf.insert(buf.end(), nested_bytes.begin(), nested_bytes.end());
			} else {
				write_varint(buf, f.bytes_value.size());
				buf.insert(buf.end(), f.bytes_value.begin(), f.bytes_value.end());
			}
			break;
		}
		case wire_type_t::fixed32: {
			uint8_t tmp[4];
			std::memcpy(tmp, &f.fixed32_value, 4);
			buf.insert(buf.end(), tmp, tmp + 4);
			break;
		}
		}
	}
	return buf;
}

inline std::vector<grpc_frame_t> parse_grpc_frames(const uint8_t* data, size_t len) {
	std::vector<grpc_frame_t> frames;
	size_t offset = 0;

	while (offset + 5 <= len) {
		grpc_frame_t frame;
		frame.compressed = data[offset];
		offset += 1;

		uint32_t msg_len = 0;
		msg_len |= static_cast<uint32_t>(data[offset + 0]) << 24;
		msg_len |= static_cast<uint32_t>(data[offset + 1]) << 16;
		msg_len |= static_cast<uint32_t>(data[offset + 2]) << 8;
		msg_len |= static_cast<uint32_t>(data[offset + 3]);
		offset += 4;

		frame.length = msg_len;

		if (offset + msg_len > len) break;

		frame.data.assign(data + offset, data + offset + msg_len);
		offset += msg_len;

		frames.push_back(std::move(frame));
	}

	return frames;
}

inline std::vector<uint8_t> encode_grpc_frames(const std::vector<grpc_frame_t>& frames) {
	std::vector<uint8_t> buf;

	for (const auto& frame : frames) {
		buf.push_back(frame.compressed);

		uint32_t msg_len = static_cast<uint32_t>(frame.data.size());
		buf.push_back(static_cast<uint8_t>((msg_len >> 24) & 0xFF));
		buf.push_back(static_cast<uint8_t>((msg_len >> 16) & 0xFF));
		buf.push_back(static_cast<uint8_t>((msg_len >> 8) & 0xFF));
		buf.push_back(static_cast<uint8_t>(msg_len & 0xFF));

		buf.insert(buf.end(), frame.data.begin(), frame.data.end());
	}

	return buf;
}

inline field_t* find_field_by_path(std::vector<field_t>& fields, const std::vector<uint32_t>& path, size_t idx) {
	if (idx >= path.size()) return nullptr;

	uint32_t target = path[idx];
	for (auto& f : fields) {
		if (f.field_number == target) {
			if (idx == path.size() - 1) return &f;
			if (f.is_nested) {
				return find_field_by_path(f.nested_fields, path, idx + 1);
			}
			return nullptr;
		}
	}
	return nullptr;
}

inline std::vector<uint32_t> parse_path(const std::string& path) {
	std::vector<uint32_t> result;
	size_t start = 0;
	while (start < path.size()) {
		size_t dot = path.find('.', start);
		if (dot == std::string::npos) dot = path.size();
		std::string part = path.substr(start, dot - start);
		if (!part.empty()) {
			char* end = nullptr;
			unsigned long val = strtoul(part.c_str(), &end, 10);
			if (end != part.c_str() + part.size()) return {};
			result.push_back(static_cast<uint32_t>(val));
		}
		start = dot + 1;
	}
	return result;
}

inline uint8_t hex_char_to_nibble(char c) {
	if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
	if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
	if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
	return 0xFF;
}

inline std::vector<uint8_t> parse_hex_string(const std::string& hex) {
	std::vector<uint8_t> result;
	size_t i = 0;
	while (i < hex.size()) {
		if (hex[i] == ' ' || hex[i] == ':') { ++i; continue; }
		if (i + 1 >= hex.size()) break;
		uint8_t hi = hex_char_to_nibble(hex[i]);
		uint8_t lo = hex_char_to_nibble(hex[i + 1]);
		if (hi == 0xFF || lo == 0xFF) break;
		result.push_back(static_cast<uint8_t>((hi << 4) | lo));
		i += 2;
	}
	return result;
}

inline bool modify_field(std::vector<field_t>& fields, const std::string& path,
                         const std::string& new_value, field_display_t type) {
	auto path_parts = parse_path(path);
	if (path_parts.empty()) return false;

	field_t* f = find_field_by_path(fields, path_parts, 0);
	if (!f) return false;

	switch (type) {
	case field_display_t::uint_val:
	case field_display_t::enum_val: {
		char* end = nullptr;
		uint64_t val = strtoull(new_value.c_str(), &end, 10);
		if (end == new_value.c_str()) return false;
		f->varint_value = val;
		f->wire_type = wire_type_t::varint;
		f->display_type = type;
		break;
	}
	case field_display_t::int_val: {
		char* end = nullptr;
		int64_t val = strtoll(new_value.c_str(), &end, 10);
		if (end == new_value.c_str()) return false;
		f->varint_value = static_cast<uint64_t>(val);
		f->wire_type = wire_type_t::varint;
		f->display_type = type;
		break;
	}
	case field_display_t::sint_val: {
		char* end = nullptr;
		int64_t val = strtoll(new_value.c_str(), &end, 10);
		if (end == new_value.c_str()) return false;
		f->varint_value = zigzag_encode(val);
		f->wire_type = wire_type_t::varint;
		f->display_type = type;
		break;
	}
	case field_display_t::bool_val: {
		if (new_value == "true" || new_value == "1") {
			f->varint_value = 1;
		} else {
			f->varint_value = 0;
		}
		f->wire_type = wire_type_t::varint;
		f->display_type = type;
		break;
	}
	case field_display_t::float_val: {
		float fval = strtof(new_value.c_str(), nullptr);
		uint32_t bits = 0;
		std::memcpy(&bits, &fval, 4);
		f->fixed32_value = bits;
		f->wire_type = wire_type_t::fixed32;
		f->display_type = type;
		break;
	}
	case field_display_t::double_val: {
		double dval = strtod(new_value.c_str(), nullptr);
		uint64_t bits = 0;
		std::memcpy(&bits, &dval, 8);
		f->fixed64_value = bits;
		f->wire_type = wire_type_t::fixed64;
		f->display_type = type;
		break;
	}
	case field_display_t::string_val: {
		f->bytes_value.assign(new_value.begin(), new_value.end());
		f->string_value = new_value;
		f->wire_type = wire_type_t::length_delimited;
		f->is_nested = false;
		f->nested_fields.clear();
		f->display_type = type;
		break;
	}
	case field_display_t::bytes_val: {
		auto bytes = parse_hex_string(new_value);
		f->bytes_value = std::move(bytes);
		f->string_value.clear();
		f->wire_type = wire_type_t::length_delimited;
		f->is_nested = false;
		f->nested_fields.clear();
		f->display_type = type;
		break;
	}
	case field_display_t::fixed32_val: {
		char* end = nullptr;
		uint32_t val = static_cast<uint32_t>(strtoul(new_value.c_str(), &end, 10));
		if (end == new_value.c_str()) return false;
		f->fixed32_value = val;
		f->wire_type = wire_type_t::fixed32;
		f->display_type = type;
		break;
	}
	case field_display_t::fixed64_val: {
		char* end = nullptr;
		uint64_t val = strtoull(new_value.c_str(), &end, 10);
		if (end == new_value.c_str()) return false;
		f->fixed64_value = val;
		f->wire_type = wire_type_t::fixed64;
		f->display_type = type;
		break;
	}
	case field_display_t::sfixed32_val: {
		char* end = nullptr;
		int32_t val = static_cast<int32_t>(strtol(new_value.c_str(), &end, 10));
		if (end == new_value.c_str()) return false;
		uint32_t bits = 0;
		std::memcpy(&bits, &val, 4);
		f->fixed32_value = bits;
		f->wire_type = wire_type_t::fixed32;
		f->display_type = type;
		break;
	}
	case field_display_t::sfixed64_val: {
		char* end = nullptr;
		int64_t val = strtoll(new_value.c_str(), &end, 10);
		if (end == new_value.c_str()) return false;
		uint64_t bits = 0;
		std::memcpy(&bits, &val, 8);
		f->fixed64_value = bits;
		f->wire_type = wire_type_t::fixed64;
		f->display_type = type;
		break;
	}
	case field_display_t::nested_message:
		return false;
	}

	return true;
}

inline std::string format_hex_byte(uint8_t b) {
	const char hex[] = "0123456789ABCDEF";
	std::string s(2, '0');
	s[0] = hex[(b >> 4) & 0x0F];
	s[1] = hex[b & 0x0F];
	return s;
}

inline std::string format_field_value(const field_t& f) {
	switch (f.display_type) {
	case field_display_t::uint_val:
		return std::to_string(f.varint_value);

	case field_display_t::sint_val:
		return std::to_string(zigzag_decode(f.varint_value));

	case field_display_t::int_val:
		return std::to_string(static_cast<int64_t>(f.varint_value));

	case field_display_t::bool_val:
		return f.varint_value ? "true" : "false";

	case field_display_t::enum_val:
		return std::to_string(f.varint_value);

	case field_display_t::float_val: {
		float fval = 0.0f;
		std::memcpy(&fval, &f.fixed32_value, 4);
		return std::to_string(fval);
	}

	case field_display_t::double_val: {
		double dval = 0.0;
		std::memcpy(&dval, &f.fixed64_value, 8);
		return std::to_string(dval);
	}

	case field_display_t::string_val: {
		if (!f.string_value.empty()) return f.string_value;
		std::string s;
		s.reserve(f.bytes_value.size());
		for (auto b : f.bytes_value) {
			if (b >= 0x20 && b <= 0x7E) {
				s.push_back(static_cast<char>(b));
			} else {
				s += "\\x";
				s += format_hex_byte(b);
			}
		}
		return s;
	}

	case field_display_t::bytes_val: {
		std::string s;
		for (size_t i = 0; i < f.bytes_value.size(); ++i) {
			if (i > 0) s += ' ';
			s += format_hex_byte(f.bytes_value[i]);
		}
		return s;
	}

	case field_display_t::nested_message:
		return "{...} (" + std::to_string(f.nested_fields.size()) + " fields)";

	case field_display_t::fixed32_val:
		return std::to_string(f.fixed32_value);

	case field_display_t::fixed64_val:
		return std::to_string(f.fixed64_value);

	case field_display_t::sfixed32_val: {
		int32_t val = 0;
		std::memcpy(&val, &f.fixed32_value, 4);
		return std::to_string(val);
	}

	case field_display_t::sfixed64_val: {
		int64_t val = 0;
		std::memcpy(&val, &f.fixed64_value, 8);
		return std::to_string(val);
	}
	}

	return "";
}

inline void auto_detect_types(std::vector<field_t>& fields) {
	for (auto& f : fields) {
		switch (f.wire_type) {
		case wire_type_t::varint: {
			if (f.varint_value == 0 || f.varint_value == 1) {
				f.display_type = field_display_t::bool_val;
			} else if (f.varint_value <= 0x7FFFFFFF) {
				f.display_type = field_display_t::int_val;
			} else {
				f.display_type = field_display_t::uint_val;
			}
			break;
		}
		case wire_type_t::fixed64: {
			f.display_type = field_display_t::fixed64_val;
			break;
		}
		case wire_type_t::fixed32: {
			f.display_type = field_display_t::fixed32_val;
			break;
		}
		case wire_type_t::length_delimited: {
			if (f.is_nested && !f.nested_fields.empty()) {
				f.display_type = field_display_t::nested_message;
				auto_detect_types(f.nested_fields);
			} else {
				bool all_printable = true;
				for (auto b : f.bytes_value) {
					if (!is_printable_byte(b)) {
						all_printable = false;
						break;
					}
				}
				if (all_printable && !f.bytes_value.empty()) {
					f.string_value.assign(f.bytes_value.begin(), f.bytes_value.end());
					f.display_type = field_display_t::string_val;
				} else {
					std::vector<field_t> nested;
					if (!f.bytes_value.empty() && try_decode_nested(f.bytes_value.data(), f.bytes_value.size(), nested, f.depth + 1)) {
						f.nested_fields = std::move(nested);
						f.is_nested = true;
						f.display_type = field_display_t::nested_message;
						auto_detect_types(f.nested_fields);
					} else {
						f.display_type = field_display_t::bytes_val;
					}
				}
			}
			break;
		}
		}
	}
}

}
