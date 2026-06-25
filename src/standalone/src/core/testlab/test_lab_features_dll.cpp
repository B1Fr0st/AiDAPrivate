#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "../runtime/standalone_driver.hpp"
#include "imgui/imgui.h"

#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <cwchar>
#include <string>
#include <vector>

namespace {

	const char* dprt_op_label(std::uint32_t op) {
		switch (op) {
			case voyager::detail::DPRT_OP_REGISTER:   return "REGISTER";
			case voyager::detail::DPRT_OP_QUERY:      return "QUERY";
			case voyager::detail::DPRT_OP_UNREGISTER: return "UNREGISTER";
			default: return "UNKNOWN";
		}
	}

	const char* dprt_status_label(std::uint32_t status) {
		switch (status) {
			case 0: return "INACTIVE";
			case voyager::detail::DPRT_STATUS_ACTIVE:   return "ACTIVE";
			case voyager::detail::DPRT_STATUS_TAMPERED: return "TAMPERED";
			case voyager::detail::DPRT_STATUS_DEBUGGER: return "DEBUGGER";
			default: return "UNKNOWN";
		}
	}

	void push_u32_hex(test_lab::result_t& r, const char* label, std::uint32_t v) {
		char b[32];
		std::snprintf(b, sizeof(b), "%u (0x%08X)", v, v);
		r.parsed.push_back({ label, b });
	}

	void push_u64_hex(test_lab::result_t& r, const char* label, std::uint64_t v) {
		char b[40];
		std::snprintf(b, sizeof(b), "0x%016llX", static_cast<unsigned long long>(v));
		r.parsed.push_back({ label, b });
	}

	void push_bool(test_lab::result_t& r, const char* label, bool v) {
		r.parsed.push_back({ label, v ? "1" : "0" });
	}

	bool parse_u64_hex_strict(const std::string& text, std::uint64_t& out) {
		out = 0;
		if (text.empty())
			return false;
		const char* p = text.c_str();
		if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
			p += 2;
		if (*p == '\0')
			return false;
		std::uint64_t acc = 0;
		std::uint32_t digits = 0;
		while (*p) {
			const char c = *p++;
			std::uint64_t d = 0;
			if (c >= '0' && c <= '9')
				d = static_cast<std::uint64_t>(c - '0');
			else if (c >= 'a' && c <= 'f')
				d = static_cast<std::uint64_t>(10 + (c - 'a'));
			else if (c >= 'A' && c <= 'F')
				d = static_cast<std::uint64_t>(10 + (c - 'A'));
			else
				return false;
			if (++digits > 16)
				return false;
			acc = (acc << 4) | d;
		}
		out = acc;
		return digits > 0;
	}

	std::uint64_t compute_dprt_hash(const std::vector<std::uint8_t>& bytes) {
		std::uint64_t h1 = 0xFFFFFFFFULL;
		std::uint64_t h2 = 0x85EBCA6BULL;
		const std::size_t aligned_end = bytes.size() & ~static_cast<std::size_t>(7);
		for (std::size_t i = 0; i < aligned_end; i += 8) {
			std::uint64_t block = 0;
			std::memcpy(&block, bytes.data() + i, sizeof(block));
			h1 = _mm_crc32_u64(h1, block);
			h2 = _mm_crc32_u64(h2, block ^ 0xA5A5A5A5A5A5A5A5ULL);
		}
		for (std::size_t i = aligned_end; i < bytes.size(); ++i) {
			h1 = _mm_crc32_u8(static_cast<unsigned int>(h1), bytes[i]);
			h2 = _mm_crc32_u8(static_cast<unsigned int>(h2), bytes[i] ^ 0xA5u);
		}
		return (h1 & 0xFFFFFFFFULL) | ((h2 & 0xFFFFFFFFULL) << 32);
	}

	std::string win32_error_text(DWORD err) {
		char b[64];
		std::snprintf(b, sizeof(b), "gle=%lu", static_cast<unsigned long>(err));
		return b;
	}

	std::wstring widen_path(const std::string& text) {
		if (text.empty())
			return {};
		int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), -1, nullptr, 0);
		UINT codepage = CP_UTF8;
		DWORD flags = MB_ERR_INVALID_CHARS;
		if (needed <= 0) {
			codepage = CP_ACP;
			flags = 0;
			needed = MultiByteToWideChar(codepage, flags, text.c_str(), -1, nullptr, 0);
		}
		if (needed <= 1)
			return {};
		std::wstring out(static_cast<std::size_t>(needed), L'\0');
		int written = MultiByteToWideChar(codepage, flags, text.c_str(), -1, &out[0], needed);
		if (written <= 1)
			return {};
		out.resize(static_cast<std::size_t>(written - 1));
		return out;
	}

	std::wstring normalize_module_path(std::wstring path, const std::string& module_name) {
		if (path.rfind(L"\\??\\", 0) == 0)
			path.erase(0, 4);
		if (_wcsnicmp(path.c_str(), L"\\SystemRoot\\", 12) == 0) {
			wchar_t win[MAX_PATH] = {};
			const UINT n = GetWindowsDirectoryW(win, MAX_PATH);
			if (n != 0 && n < MAX_PATH)
				path = std::wstring(win, n) + path.substr(11);
		}
		if (!path.empty())
			return path;
		wchar_t sys[MAX_PATH] = {};
		const UINT n = GetSystemDirectoryW(sys, MAX_PATH);
		if (n == 0 || n >= MAX_PATH)
			return {};
		std::wstring name = widen_path(module_name);
		if (name.empty())
			return {};
		std::wstring out(sys, n);
		if (!out.empty() && out.back() != L'\\')
			out.push_back(L'\\');
		out += name;
		return out;
	}

	struct dprt_known_good_fixture_t {
		bool ok = false;
		std::uint64_t module_base = 0;
		std::uint32_t module_size = 0;
		std::uint64_t rva = 0;
		std::uint64_t hash = 0;
		std::string module_name;
		std::string module_path;
		std::string source;
		std::string error;
	};

	bool read_clean_image_range(const std::wstring& path,
		std::uint64_t rva,
		std::uint32_t size,
		std::vector<std::uint8_t>& out,
		std::string& error) {
		out.clear();
		if (path.empty() || rva == 0 || size == 0) {
			error = "invalid_clean_image_input";
			return false;
		}
		HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			error = "CreateFileW " + win32_error_text(GetLastError());
			return false;
		}
		HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
		if (!mapping) {
			const DWORD gle = GetLastError();
			CloseHandle(file);
			error = "CreateFileMappingW_SEC_IMAGE " + win32_error_text(gle);
			return false;
		}
		void* view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
		if (!view) {
			const DWORD gle = GetLastError();
			CloseHandle(mapping);
			CloseHandle(file);
			error = "MapViewOfFile " + win32_error_text(gle);
			return false;
		}
		bool ok = false;
		do {
			const auto* base = static_cast<const std::uint8_t*>(view);
			const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
			if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
				error = "clean_image_bad_dos_signature";
				break;
			}
			const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + static_cast<std::uint32_t>(dos->e_lfanew));
			if (nt->Signature != IMAGE_NT_SIGNATURE) {
				error = "clean_image_bad_nt_signature";
				break;
			}
			const std::uint64_t image_size = nt->OptionalHeader.SizeOfImage;
			if (rva >= image_size || size > image_size - rva) {
				error = "clean_image_rva_out_of_range";
				break;
			}
			out.resize(size);
			std::memcpy(out.data(), base + rva, size);
			ok = true;
		} while (false);
		UnmapViewOfFile(view);
		CloseHandle(mapping);
		CloseHandle(file);
		return ok;
	}

	dprt_known_good_fixture_t prepare_dprt_known_good_fixture(const test_lab::state_t& s) {
		dprt_known_good_fixture_t fixture{};
		if (s.pid == 0 || s.addr == 0 || s.size == 0) {
			fixture.error = "missing_pid_addr_or_size";
			return fixture;
		}
		const std::uint64_t end = s.addr + static_cast<std::uint64_t>(s.size);
		if (end <= s.addr) {
			fixture.error = "address_range_overflow";
			return fixture;
		}
		auto modules = driver_bridge::enumerate_modules_for(s.pid);
		for (const auto& mod : modules) {
			if (mod.base == 0 || mod.size == 0)
				continue;
			const std::uint64_t mod_end = mod.base + static_cast<std::uint64_t>(mod.size);
			if (mod_end <= mod.base)
				continue;
			if (s.addr >= mod.base && end <= mod_end) {
				fixture.module_base = mod.base;
				fixture.module_size = mod.size;
				fixture.module_name = mod.name;
				fixture.module_path = mod.path;
				break;
			}
		}
		if (fixture.module_base == 0) {
			fixture.error = "remote_module_not_found_for_range";
			return fixture;
		}
		fixture.rva = s.addr - fixture.module_base;
		std::wstring path = normalize_module_path(widen_path(fixture.module_path), fixture.module_name);
		std::vector<std::uint8_t> clean_bytes;
		std::string image_error;
		if (!read_clean_image_range(path, fixture.rva, s.size, clean_bytes, image_error)) {
			fixture.error = image_error;
			return fixture;
		}
		fixture.hash = compute_dprt_hash(clean_bytes);
		fixture.source = "provided_verified_clean_image_fixture";
		fixture.ok = fixture.hash != 0;
		if (!fixture.ok)
			fixture.error = "clean_image_hash_zero";
		return fixture;
	}

	void render_inputs_dprt(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");

		const char* items[] = { "REGISTER (0)", "QUERY (1)", "UNREGISTER (2)" };
		int sel = 1;
		if (s.u32_a == voyager::detail::DPRT_OP_REGISTER)   sel = 0;
		else if (s.u32_a == voyager::detail::DPRT_OP_QUERY)      sel = 1;
		else if (s.u32_a == voyager::detail::DPRT_OP_UNREGISTER) sel = 2;
		if (ImGui::Combo("Operation", &sel, items, IM_ARRAYSIZE(items))) {
			if (sel == 0) s.u32_a = voyager::detail::DPRT_OP_REGISTER;
			else if (sel == 1) s.u32_a = voyager::detail::DPRT_OP_QUERY;
			else if (sel == 2) s.u32_a = voyager::detail::DPRT_OP_UNREGISTER;
		}

		char name_buf[260];
		std::snprintf(name_buf, sizeof(name_buf), "%s", s.text_a.c_str());
		if (ImGui::InputText("DLL name pattern (informational)", name_buf, sizeof(name_buf))) {
			s.text_a.assign(name_buf);
		}

		if (s.u32_a == voyager::detail::DPRT_OP_REGISTER) {
			ImGui::InputScalar("module_base (u64_a)", ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
			ImGui::InputScalar("text_section_va (addr)", ImGuiDataType_U64, &s.addr, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
			ImGui::InputScalar("text size (size)",    ImGuiDataType_U32, &s.size,  nullptr, nullptr, "%u");
			ImGui::InputScalar("check_interval (u32_b, ms)", ImGuiDataType_U32, &s.u32_b, nullptr, nullptr, "%u");
			char hex_buf[64];
			std::snprintf(hex_buf, sizeof(hex_buf), "%s", s.text_b.c_str());
			if (ImGui::InputText("expected_hash hex (text_b)", hex_buf, sizeof(hex_buf), ImGuiInputTextFlags_CharsHexadecimal)) {
				s.text_b.assign(hex_buf);
			}
		}
		ImGui::TextDisabled("Note: kernel dll_protect struct has no name-pattern field; protection keys on (pid, module_base, text_va) text-section hash. text_a is preserved for protocol/log use.");
	}

	void run_dprt(test_lab::state_t& s, test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		std::uint64_t expected_hash = 0;
		const bool input_supplied_hash = parse_u64_hex_strict(s.text_b, expected_hash);
		dprt_known_good_fixture_t fixture{};
		if (s.u32_a == voyager::detail::DPRT_OP_REGISTER && (!input_supplied_hash || expected_hash == 0))
			fixture = prepare_dprt_known_good_fixture(s);
		const bool fixture_supplied_hash = fixture.ok;
		if (fixture_supplied_hash)
			expected_hash = fixture.hash;
		const bool supplied_hash = input_supplied_hash || fixture_supplied_hash;
		const std::uint64_t effective_module_base = s.u64_a != 0 ? s.u64_a : fixture.module_base;

		voyager::detail::dll_protect_request req{};
		req.operation         = s.u32_a;
		req.pid               = s.pid;
		req.module_base       = effective_module_base;
		req.text_section_va   = s.addr;
		req.text_section_size = s.size;
		req.expected_hash     = expected_hash;
		req.check_interval    = s.u32_b;

		if (s.u32_a == voyager::detail::DPRT_OP_REGISTER) {
			if (s.pid == 0) {
				r.ok = false;
				r.error = "REGISTER requires a non-zero PID";
				return;
			}
			if (s.addr == 0 || s.size == 0) {
				r.ok = false;
				r.error = "REGISTER requires text_section_va and text size to be non-zero";
				return;
			}
			if (s.size > 0x100000u) {
				r.ok = false;
				r.error = "REGISTER text size exceeds safe Test Lab cap";
				r.ntstatus = static_cast<std::int32_t>(0xC0000206u);
				return;
			}
			if (effective_module_base == 0 && s.pid == GetCurrentProcessId()) {
				r.ok = false;
				r.error = "diagnostic module_base=0 DPRT registration is not allowed for the AiDA process";
				r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
				return;
			}
			r.parsed.push_back({ "module_base_policy", effective_module_base == 0 ? "diagnostic_fail_closed" : "module_hard_bugcheck" });
			r.parsed.push_back({ "module_base_source", s.u64_a == 0 ? (fixture.module_base != 0 ? "inferred_remote_module" : "missing") : "input" });
			if (!fixture.module_name.empty())
				r.parsed.push_back({ "known_good_module", fixture.module_name });
			if (!fixture.module_path.empty())
				r.parsed.push_back({ "known_good_module_path", fixture.module_path });
			push_u64_hex(r, "known_good_module_base", fixture.module_base);
			push_u32_hex(r, "known_good_module_size", fixture.module_size);
			push_u64_hex(r, "known_good_rva", fixture.rva);
			push_bool(r, "known_good_fixture_ok", fixture.ok);
			if (!fixture.error.empty())
				r.parsed.push_back({ "known_good_fixture_error", fixture.error });

			std::vector<std::uint8_t> baseline;
			const bool read_ok = driver_bridge::read_memory_for(s.pid, s.addr, s.size, baseline);
			push_bool(r, "baseline_read_ok", read_ok);
			push_u32_hex(r, "baseline_requested_size", s.size);
			push_u32_hex(r, "baseline_bytes_read", static_cast<std::uint32_t>(baseline.size()));
			if (!read_ok || baseline.size() != s.size) {
				r.ok = false;
				r.error = "failed to read exact DPRT baseline bytes from target";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				return;
			}

			const std::uint64_t live_hash = compute_dprt_hash(baseline);
			push_bool(r, "expected_hash_supplied", supplied_hash);
			r.parsed.push_back({ "expected_hash_input_source", input_supplied_hash ? "text_b" : (fixture_supplied_hash ? fixture.source : "missing") });
			push_bool(r, "expected_hash_prepared_before_live_baseline", fixture_supplied_hash);
			push_u64_hex(r, "live_baseline_hash", live_hash);
			if (!supplied_hash || expected_hash == 0) {
				r.parsed.push_back({ "expected_hash_source", "computed_live_baseline_diagnostic" });
				r.parsed.push_back({ "live_baseline_role", "diagnostic_only" });
				push_bool(r, "dprt_functional_pass_eligible", false);
				r.ok = false;
				r.error = "DPRT functional registration requires a supplied known-good expected_hash; live baseline is diagnostic only";
				r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
				return;
			} else if (expected_hash != live_hash) {
				r.parsed.push_back({ "expected_hash_source", fixture_supplied_hash ? fixture.source : "provided_text_b" });
				r.parsed.push_back({ "live_baseline_role", "diagnostic_mismatch_fail_closed" });
				r.ok = false;
				r.error = "provided expected_hash does not match live target bytes; refusing to arm bugcheckable DPRT slot";
				r.ntstatus = static_cast<std::int32_t>(0xC0000022u);
				return;
			} else {
				r.parsed.push_back({ "expected_hash_source", fixture_supplied_hash ? fixture.source : "provided_verified_text_b" });
				r.parsed.push_back({ "live_baseline_role", "diagnostic_crosscheck_only" });
				push_bool(r, "dprt_functional_pass_eligible", true);
			}
			if (req.check_interval == 0)
				req.check_interval = 30000u;
			push_u32_hex(r, "effective_check_interval_ms", req.check_interval);
		} else if (!s.text_b.empty() && !supplied_hash) {
			r.parsed.push_back({ "expected_hash_input", "ignored_non_hex" });
		}

		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::DPRT(), &req,
			static_cast<std::uint32_t>(sizeof(req)), bytes_returned);
		r.bytes_returned = bytes_returned;
		r.raw.resize(sizeof(req));
		std::memcpy(r.raw.data(), &req, sizeof(req));
		if (!ok) {
			r.ok = false;
			r.error = "send_ioctl_raw returned false";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		if (s.u32_a == voyager::detail::DPRT_OP_REGISTER) {
			r.parsed.push_back({ "register_status", dprt_status_label(req.status) });
			push_u32_hex(r, "register_bytes_returned", bytes_returned);
			if (req.status != voyager::detail::DPRT_STATUS_ACTIVE || req.current_hash != req.expected_hash) {
				voyager::detail::dll_protect_request cleanup{};
				cleanup.operation = voyager::detail::DPRT_OP_UNREGISTER;
				cleanup.pid = s.pid;
				cleanup.module_base = req.module_base;
				std::uint32_t cleanup_bytes = 0;
				device->send_ioctl_raw(ioctl_codes::DPRT(), &cleanup, static_cast<std::uint32_t>(sizeof(cleanup)), cleanup_bytes);
				r.ok = false;
				r.error = "DPRT register did not return active matching status";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				return;
			}

			voyager::detail::dll_protect_request query{};
			query.operation = voyager::detail::DPRT_OP_QUERY;
			query.pid = s.pid;
			query.module_base = req.module_base;
			std::uint32_t query_bytes = 0;
			const bool query_ok = device->send_ioctl_raw(ioctl_codes::DPRT(), &query,
				static_cast<std::uint32_t>(sizeof(query)), query_bytes);
			push_bool(r, "query_after_register_ok", query_ok);
			push_u32_hex(r, "query_after_register_bytes", query_bytes);
			r.parsed.push_back({ "query_after_register_status", dprt_status_label(query.status) });
			push_u64_hex(r, "query_after_register_current_hash", query.current_hash);

			voyager::detail::dll_protect_request unreg{};
			unreg.operation = voyager::detail::DPRT_OP_UNREGISTER;
			unreg.pid = s.pid;
			unreg.module_base = req.module_base;
			std::uint32_t unreg_bytes = 0;
			const bool unreg_ok = device->send_ioctl_raw(ioctl_codes::DPRT(), &unreg,
				static_cast<std::uint32_t>(sizeof(unreg)), unreg_bytes);
			push_bool(r, "unregister_ok", unreg_ok);
			push_u32_hex(r, "unregister_bytes", unreg_bytes);
			r.parsed.push_back({ "unregister_status", dprt_status_label(unreg.status) });

			voyager::detail::dll_protect_request post{};
			post.operation = voyager::detail::DPRT_OP_QUERY;
			post.pid = s.pid;
			post.module_base = req.module_base;
			std::uint32_t post_bytes = 0;
			const bool post_ok = device->send_ioctl_raw(ioctl_codes::DPRT(), &post,
				static_cast<std::uint32_t>(sizeof(post)), post_bytes);
			push_bool(r, "query_after_unregister_ok", post_ok);
			push_u32_hex(r, "query_after_unregister_bytes", post_bytes);
			r.parsed.push_back({ "query_after_unregister_status", dprt_status_label(post.status) });
			r.ok = query_ok &&
				unreg_ok &&
				post_ok &&
				query.status == voyager::detail::DPRT_STATUS_ACTIVE &&
				query.current_hash == expected_hash &&
				post.status == voyager::detail::DPRT_STATUS_INACTIVE;
			if (!r.ok) {
				r.error = "DPRT register/query/unregister round-trip did not verify all expected states";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				return;
			}
			r.parsed.push_back({ "dprt_functional_proof", "provided_hash_register_query_unregister" });
		}

		r.parsed.push_back({ "operation", dprt_op_label(req.operation) });
		push_u32_hex(r, "pid",            req.pid);
		push_u64_hex(r, "module_base",    req.module_base);
		push_u64_hex(r, "text_section_va",   req.text_section_va);
		push_u32_hex(r, "text_section_size", req.text_section_size);
		push_u64_hex(r, "expected_hash",  req.expected_hash);
		push_u64_hex(r, "current_hash",   req.current_hash);
		r.parsed.push_back({ "status", dprt_status_label(req.status) });
		push_u32_hex(r, "check_interval_ms", req.check_interval);
		push_u64_hex(r, "last_check_tsc", req.last_check_tsc);
		if (!s.text_a.empty()) {
			r.parsed.push_back({ "name_pattern (informational)", s.text_a });
		}
		r.ok = true;
	}

}

TESTLAB_REGISTER(g_reg_dprt, "dll", test_lab::driver_e::whoswho, "DPRT",
	"DLL load protect register/query/unregister (kernel hashes a target module's .text section per PID).",
	&render_inputs_dprt, &run_dprt);
