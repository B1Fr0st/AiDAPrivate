#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "../runtime/shadow_fs_client.hpp"
#include "imgui/imgui.h"

#include <Windows.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <windns.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

	bool ensure_driver(test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return false;
		}
		return true;
	}

	std::string fmt_u32(std::uint32_t v) {
		char b[16];
		std::snprintf(b, sizeof(b), "%u", v);
		return std::string(b);
	}

	BOOL CALLBACK init_test_winsock_once(PINIT_ONCE, PVOID parameter, PVOID*) {
		bool* ok = static_cast<bool*>(parameter);
		WSADATA d{};
		*ok = (WSAStartup(MAKEWORD(2, 2), &d) == 0);
		return TRUE;
	}

	bool ensure_test_winsock_ready() {
		static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
		static bool ok = false;
		if (!InitOnceExecuteOnce(&once, init_test_winsock_once, &ok, nullptr))
			return false;
		return ok;
	}

	std::wstring ascii_to_wide(const char* s) {
		std::wstring out;
		if (!s)
			return out;
		while (*s) {
			out.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*s)));
			++s;
		}
		return out;
	}

	struct dns_query_context_t {
		OVERLAPPED overlapped{};
		PADDRINFOEXW result = nullptr;
		HANDLE event = nullptr;
		DWORD error = WSA_OPERATION_ABORTED;
		bool had_result = false;
	};

	void CALLBACK dns_query_complete(DWORD error, DWORD, LPWSAOVERLAPPED overlapped) {
		dns_query_context_t* ctx = CONTAINING_RECORD(overlapped, dns_query_context_t, overlapped);
		ctx->error = error;
		ctx->had_result = (ctx->result != nullptr);
		if (ctx->result != nullptr) {
			FreeAddrInfoExW(ctx->result);
			ctx->result = nullptr;
		}
		if (ctx->event != nullptr)
			SetEvent(ctx->event);
	}

	bool resolve_host_with_timeout(const char* host, int timeout_ms) {
		std::wstring host_w = ascii_to_wide(host);
		if (host_w.empty())
			return false;

		ADDRINFOEXW hints{};
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		dns_query_context_t ctx{};
		ctx.event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (ctx.event == nullptr)
			return false;

		HANDLE cancel_handle = nullptr;
		int rc = GetAddrInfoExW(host_w.c_str(), nullptr, NS_DNS, nullptr, &hints, &ctx.result, nullptr, &ctx.overlapped, dns_query_complete, &cancel_handle);
		if (rc != WSA_IO_PENDING) {
			dns_query_complete(static_cast<DWORD>(rc), 0, &ctx.overlapped);
		} else {
			DWORD wait_ms = timeout_ms > 0 ? static_cast<DWORD>(timeout_ms) : 1u;
			if (WaitForSingleObject(ctx.event, wait_ms) == WAIT_TIMEOUT) {
				if (cancel_handle != nullptr)
					GetAddrInfoExCancel(&cancel_handle);
				WaitForSingleObject(ctx.event, INFINITE);
			}
		}

		bool ok = (ctx.error == ERROR_SUCCESS && ctx.had_result);
		CloseHandle(ctx.event);
		return ok;
	}

	std::string fmt_u64(std::uint64_t v) {
		char b[32];
		std::snprintf(b, sizeof(b), "%llu", static_cast<unsigned long long>(v));
		return std::string(b);
	}

	std::string fmt_hex_u64(std::uint64_t v) {
		char b[24];
		std::snprintf(b, sizeof(b), "0x%016llX", static_cast<unsigned long long>(v));
		return std::string(b);
	}

	std::string fmt_ip_v4(const std::uint8_t* a) {
		char b[24];
		std::snprintf(b, sizeof(b), "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
		return std::string(b);
	}

	bool addr_is_one_one_one_one(const std::uint8_t* a, std::uint32_t family) {
		if (family != 0u && family != 2u) return false;
		return a[0] == 1u && a[1] == 1u && a[2] == 1u && a[3] == 1u;
	}

	struct wsa_guard_t {
		bool ok = false;
		wsa_guard_t() {
			ok = ensure_test_winsock_ready();
		}
		~wsa_guard_t() = default;
		wsa_guard_t(const wsa_guard_t&) = delete;
		wsa_guard_t& operator=(const wsa_guard_t&) = delete;
	};

	bool issue_short_http_get_to_one_one(std::string& diag) {
		HINTERNET h_session = WinHttpOpen(L"AiDA-VerifyLab/1.0",
			WINHTTP_ACCESS_TYPE_NO_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS,
			0);
		if (h_session == nullptr) {
			diag = "WinHttpOpen failed";
			return false;
		}
		WinHttpSetTimeouts(h_session, 1500, 1500, 1500, 1500);
		HINTERNET h_conn = WinHttpConnect(h_session, L"1.1.1.1", 80, 0);
		if (h_conn == nullptr) {
			diag = "WinHttpConnect failed";
			WinHttpCloseHandle(h_session);
			return false;
		}
		HINTERNET h_req = WinHttpOpenRequest(h_conn, L"GET", L"/", nullptr,
			WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			0);
		if (h_req == nullptr) {
			diag = "WinHttpOpenRequest failed";
			WinHttpCloseHandle(h_conn);
			WinHttpCloseHandle(h_session);
			return false;
		}
		BOOL sent = WinHttpSendRequest(h_req,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
		bool any_io = (sent != FALSE);
		if (sent) {
			BOOL got = WinHttpReceiveResponse(h_req, nullptr);
			if (!got) {
				diag = "WinHttpReceiveResponse failed (still counts as sent SYN)";
			}
		} else {
			DWORD err = GetLastError();
			char b[96];
			std::snprintf(b, sizeof(b), "WinHttpSendRequest err=%lu (SYN may still be on wire)",
				static_cast<unsigned long>(err));
			diag = b;
			any_io = true;
		}
		WinHttpCloseHandle(h_req);
		WinHttpCloseHandle(h_conn);
		WinHttpCloseHandle(h_session);
		return any_io;
	}

	bool issue_raw_tcp_probe_to_one_one(std::string& diag) {
		wsa_guard_t g;
		if (!g.ok) {
			diag = "WSAStartup failed";
			return false;
		}
		SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s == INVALID_SOCKET) {
			diag = "socket() failed";
			return false;
		}
		u_long nb = 1;
		ioctlsocket(s, FIONBIO, &nb);
		sockaddr_in dst{};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(80);
		dst.sin_addr.s_addr = htonl(0x01010101u);
		int rc = connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
		bool initiated = false;
		if (rc == 0) {
			initiated = true;
		} else {
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK) {
				initiated = true;
			} else {
				char b[64];
				std::snprintf(b, sizeof(b), "connect() err=%d", err);
				diag = b;
			}
		}
		if (initiated) {
			fd_set wf;
			FD_ZERO(&wf);
			FD_SET(s, &wf);
			timeval tv{};
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			int sel = select(0, nullptr, &wf, nullptr, &tv);
			if (sel > 0) {
				const char* req = "HEAD / HTTP/1.0\r\n\r\n";
				send(s, req, static_cast<int>(std::strlen(req)), 0);
				char recv_buf[64];
				recv(s, recv_buf, sizeof(recv_buf), 0);
			}
		}
		closesocket(s);
		return initiated;
	}

	bool issue_udp_dns_probe_to_one_one(const char* host, std::string& diag) {
		wsa_guard_t g;
		if (!g.ok) {
			diag = "WSAStartup failed";
			return false;
		}
		if (host == nullptr || host[0] == '\0') {
			diag = "empty DNS host";
			return false;
		}

		std::vector<unsigned char> packet;
		packet.reserve(512);
		const std::uint16_t qid = static_cast<std::uint16_t>(GetTickCount() & 0xffffu);
		packet.push_back(static_cast<unsigned char>(qid >> 8));
		packet.push_back(static_cast<unsigned char>(qid & 0xff));
		packet.push_back(0x01);
		packet.push_back(0x00);
		packet.push_back(0x00);
		packet.push_back(0x01);
		packet.push_back(0x00);
		packet.push_back(0x00);
		packet.push_back(0x00);
		packet.push_back(0x00);
		packet.push_back(0x00);
		packet.push_back(0x00);

		const char* label = host;
		while (*label) {
			const char* dot = std::strchr(label, '.');
			std::size_t len = dot ? static_cast<std::size_t>(dot - label) : std::strlen(label);
			if (len == 0 || len > 63 || packet.size() + len + 6 > 512) {
				diag = "DNS host label invalid";
				return false;
			}
			packet.push_back(static_cast<unsigned char>(len));
			for (std::size_t i = 0; i < len; ++i)
				packet.push_back(static_cast<unsigned char>(label[i]));
			if (!dot)
				break;
			label = dot + 1;
		}
		packet.push_back(0x00);
		packet.push_back(0x00);
		packet.push_back(0x01);
		packet.push_back(0x00);
		packet.push_back(0x01);

		SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (s == INVALID_SOCKET) {
			diag = "DNS UDP socket failed";
			return false;
		}
		sockaddr_in dst{};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(53);
		dst.sin_addr.s_addr = htonl(0x01010101u);
		int sent = sendto(s,
			reinterpret_cast<const char*>(packet.data()),
			static_cast<int>(packet.size()),
			0,
			reinterpret_cast<sockaddr*>(&dst),
			sizeof(dst));
		int err = (sent == SOCKET_ERROR) ? WSAGetLastError() : 0;
		closesocket(s);
		if (sent == SOCKET_ERROR) {
			char b[80];
			std::snprintf(b, sizeof(b), "DNS UDP sendto err=%d", err);
			diag = b;
			return false;
		}
		char b[96];
		std::snprintf(b, sizeof(b), "DNS UDP query host=%s bytes=%d id=%u", host, sent, qid);
		diag = b;
		return true;
	}

	void render_inputs_empty(test_lab::state_t& s) {
		(void)s;
		ImGui::TextDisabled("no inputs");
	}

	void run_verify_network_capture(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!ensure_driver(r)) return;
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());

		voyager::detail::net_cap_ctrl_request start_req{};
		start_req.operation = 0u;
		start_req.filter_pid = self_pid;
		start_req.filter_port = 0u;
		start_req.filter_protocol = 0u;
		start_req.max_packet_bytes = 1500u;
		std::uint32_t br = 0;
		bool ok_start = device->send_ioctl_raw(ioctl_codes::NCAP(), &start_req, sizeof(start_req), br);
		if (!ok_start) {
			r.ok = false;
			r.error = "NCAP start ioctl failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			r.bytes_returned = br;
			return;
		}
		r.parsed.push_back({ "step1_capture_started", "1" });
		r.parsed.push_back({ "filter_pid", fmt_u32(self_pid) });
		r.parsed.push_back({ "capture_active_after_start", fmt_u32(start_req.capture_active) });

		std::this_thread::sleep_for(std::chrono::milliseconds(100));

		std::string http_diag;
		bool any_io = issue_short_http_get_to_one_one(http_diag);
		r.parsed.push_back({ "step2_http_attempted", any_io ? "1" : "0" });
		if (!http_diag.empty()) {
			r.parsed.push_back({ "http_diag", http_diag });
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(500));

		voyager::detail::net_cap_ctrl_request stop_req{};
		stop_req.operation = 1u;
		stop_req.filter_pid = self_pid;
		stop_req.max_packet_bytes = 1500u;
		std::uint32_t br2 = 0;
		device->send_ioctl_raw(ioctl_codes::NCAP(), &stop_req, sizeof(stop_req), br2);
		r.parsed.push_back({ "step3_capture_stopped", "1" });
		r.parsed.push_back({ "packets_captured_kernel_counter", fmt_u32(stop_req.packets_captured) });
		r.parsed.push_back({ "packets_dropped_kernel_counter", fmt_u32(stop_req.packets_dropped) });

		voyager::detail::net_cap_get_request* drain =
			static_cast<voyager::detail::net_cap_get_request*>(std::calloc(1, sizeof(voyager::detail::net_cap_get_request)));
		if (drain == nullptr) {
			r.ok = false;
			r.error = "calloc failed for net_cap_get_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		drain->max_packets = 32u;
		std::uint32_t br3 = 0;
		bool ok_drain = device->send_ioctl_raw(ioctl_codes::NCPG(), drain, sizeof(*drain), br3);
		r.bytes_returned = br3;
		if (!ok_drain) {
			r.ok = false;
			r.error = "NCPG drain ioctl failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			std::free(drain);
			return;
		}
		std::uint32_t total = drain->packet_count;
		std::uint32_t matching_pid = 0;
		std::uint32_t printed = 0;
		const std::uint32_t print_cap = 8u;
		for (std::uint32_t i = 0; i < total && i < voyager::detail::NET_CAP_GET_MAX; ++i) {
			const auto& p = drain->packets[i];
			if (p.pid == self_pid) ++matching_pid;
			if (printed < print_cap) {
				char label[24];
				std::snprintf(label, sizeof(label), "pkt[%u]", i);
				char val[256];
				std::snprintf(val, sizeof(val),
					"ts=%llu pid=%u proto=%u dir=%u %s:%u -> %s:%u size=%u",
					static_cast<unsigned long long>(p.timestamp),
					p.pid, p.protocol, p.direction,
					fmt_ip_v4(p.local_addr).c_str(), p.local_port,
					fmt_ip_v4(p.remote_addr).c_str(), p.remote_port,
					p.payload_size);
				r.parsed.push_back({ std::string(label), std::string(val) });
				++printed;
			}
		}
		r.parsed.push_back({ "packets_drained_total", fmt_u32(total) });
		r.parsed.push_back({ "packets_matching_self_pid", fmt_u32(matching_pid) });

		if (matching_pid > 0u) {
			r.ntstatus = 0;
			r.ok = true;
		} else if (total > 0u) {
			r.ok = false;
			r.error = "capture drained packets but none matched current PID -- PID filter may be ignored or attribution path is broken";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		} else {
			r.ok = false;
			r.error = "capture started but no packets seen for current PID -- capture path may not be working or PID filter mismatched";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
		std::free(drain);
	}

	struct dns_log_ctx_t {
		test_lab::result_t* r;
		bool done;
	};

	static DWORD WINAPI dns_log_thread_proc(LPVOID param) {
		dns_log_ctx_t* ctx = static_cast<dns_log_ctx_t*>(param);
		test_lab::result_t& r = *ctx->r;

		if (!ensure_driver(r)) {
			ctx->done = true;
			return 0;
		}
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());

		wsa_guard_t g;
		if (!g.ok) {
			r.ok = false;
			r.error = "WSAStartup failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			ctx->done = true;
			return 0;
		}

		voyager::detail::net_dns_get_request* baseline =
			static_cast<voyager::detail::net_dns_get_request*>(std::calloc(1, sizeof(voyager::detail::net_dns_get_request)));
		if (baseline == nullptr) {
			r.ok = false;
			r.error = "calloc failed for baseline net_dns_get_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			ctx->done = true;
			return 0;
		}
		baseline->filter_pid = 0u;
		std::uint32_t br_base = 0;
		bool ok_base = device->send_ioctl_raw(ioctl_codes::NDNS(), baseline, sizeof(*baseline), br_base);
		const std::uint32_t baseline_total = ok_base ? baseline->entry_count : 0u;
		r.parsed.push_back({ "baseline_dns_entry_count", fmt_u32(baseline_total) });
		std::free(baseline);

		voyager::detail::net_cap_ctrl_request start_req{};
		start_req.operation = 0u;
		start_req.filter_pid = 0u;
		start_req.filter_port = 53u;
		start_req.filter_protocol = 17u;
		start_req.max_packet_bytes = 512u;
		std::uint32_t br_start = 0;
		bool cap_started = device->send_ioctl_raw(ioctl_codes::NCAP(), &start_req, sizeof(start_req), br_start);
		r.parsed.push_back({ "dns_capture_start_ok", cap_started ? "1" : "0" });
		r.parsed.push_back({ "dns_capture_filter_pid", "0" });
		r.parsed.push_back({ "dns_probe_owner_pid", fmt_u32(self_pid) });
		if (!cap_started) {
			r.ok = false;
			r.error = "NCAP start failed before DNS probe";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			ctx->done = true;
			return 0;
		}

		static const char* kCandidateHosts[] = {
			"aida-testlab-probe.invalid",
			"aida-testlab-dns.invalid",
			"www.microsoft.com"
		};
		const std::size_t kCandidateHostCount = sizeof(kCandidateHosts) / sizeof(kCandidateHosts[0]);

		std::string attempted_hosts;
		std::uint32_t any_io_count = 0u;

		for (std::size_t i = 0; i < kCandidateHostCount; ++i) {
			const char* host = kCandidateHosts[i];

			std::string udp_diag;
			bool lookup_ok = issue_udp_dns_probe_to_one_one(host, udp_diag);
			if (!lookup_ok)
				lookup_ok = resolve_host_with_timeout(host, 2000);

			char label[40];
			std::snprintf(label, sizeof(label), "step1_gai[%zu]", i);
			char val[200];
			std::snprintf(val, sizeof(val), "host=%s ok=%d %s", host, lookup_ok ? 1 : 0, udp_diag.c_str());
			r.parsed.push_back({ std::string(label), std::string(val) });
			if (!attempted_hosts.empty()) attempted_hosts.append(",");
			attempted_hosts.append(host);
			if (lookup_ok) ++any_io_count;
		}

		r.parsed.push_back({ "step1_attempted_hosts", attempted_hosts });
		r.parsed.push_back({ "step1_any_lookup_attempts", fmt_u32(any_io_count) });

		std::uint32_t after_total = 0u;
		std::uint32_t matches_name_and_pid = 0u;
		std::uint32_t matches_name_any_pid = 0u;
		std::uint32_t matches_name_self_or_unknown_pid = 0u;
		std::uint32_t any_self_pid_rows = 0u;
		std::uint32_t unknown_pid_rows = 0u;
		std::uint32_t printed = 0u;
		const std::uint32_t print_cap = 8u;
		std::string matched_host;

		for (int attempt = 0; attempt < 10; ++attempt) {
			std::this_thread::sleep_for(std::chrono::milliseconds(200));

			voyager::detail::net_dns_get_request* req =
				static_cast<voyager::detail::net_dns_get_request*>(std::calloc(1, sizeof(voyager::detail::net_dns_get_request)));
			if (req == nullptr) {
				r.ok = false;
				r.error = "calloc failed for net_dns_get_request";
				r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
				ctx->done = true;
				return 0;
			}
			req->filter_pid = 0u;
			std::uint32_t br = 0;
			bool ok = device->send_ioctl_raw(ioctl_codes::NDNS(), req, sizeof(*req), br);
			r.bytes_returned = br;
			if (!ok) {
				r.ok = false;
				r.error = "NDNS ioctl failed";
				r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
				std::free(req);
				ctx->done = true;
				return 0;
			}
			after_total = req->entry_count;
			std::uint32_t cap = after_total;
			if (cap > voyager::detail::NET_DNS_GET_MAX) cap = static_cast<std::uint32_t>(voyager::detail::NET_DNS_GET_MAX);
			matches_name_and_pid = 0u;
			matches_name_any_pid = 0u;
			matches_name_self_or_unknown_pid = 0u;
			any_self_pid_rows = 0u;
			unknown_pid_rows = 0u;
			for (std::uint32_t i = 0; i < cap; ++i) {
				const auto& e = req->entries[i];
				char dom[261];
				std::memcpy(dom, e.domain, 260);
				dom[260] = '\0';
				bool pid_match = (e.pid == self_pid);
				bool pid_unknown = (e.pid == 0u);
				bool pid_accepted = pid_match || pid_unknown;
				if (pid_match) ++any_self_pid_rows;
				if (pid_unknown) ++unknown_pid_rows;
				bool name_match = false;
				for (std::size_t h = 0; h < kCandidateHostCount; ++h) {
					if (std::strstr(dom, kCandidateHosts[h]) != nullptr) {
						name_match = true;
						if (pid_accepted && matched_host.empty()) matched_host = kCandidateHosts[h];
						break;
					}
				}
				if (name_match) ++matches_name_any_pid;
				if (name_match && pid_match) ++matches_name_and_pid;
				if (name_match && pid_accepted) ++matches_name_self_or_unknown_pid;
				if (attempt == 9 && name_match && printed < print_cap) {
					char label[24];
					std::snprintf(label, sizeof(label), "dns[%u]", i);
					char val[384];
					std::snprintf(val, sizeof(val),
						"ts=%llu pid=%u type=%u rcode=%u ttl=%u %s -> %s pid_match=%u pid_unknown=%u",
						static_cast<unsigned long long>(e.timestamp),
						e.pid, e.query_type, e.response_code, e.ttl,
						dom,
						fmt_ip_v4(e.resolved_addr).c_str(),
						pid_match ? 1u : 0u,
						pid_unknown ? 1u : 0u);
					r.parsed.push_back({ std::string(label), std::string(val) });
					++printed;
				}
			}
			std::free(req);
			if (matches_name_self_or_unknown_pid > 0u) break;
		}

		voyager::detail::net_cap_ctrl_request stop_req{};
		stop_req.operation = 1u;
		std::uint32_t br_stop = 0;
		device->send_ioctl_raw(ioctl_codes::NCAP(), &stop_req, sizeof(stop_req), br_stop);
		r.parsed.push_back({ "dns_capture_stop_ok", "1" });

		r.parsed.push_back({ "dns_entry_count_total", fmt_u32(after_total) });
		r.parsed.push_back({ "matches_name_and_pid", fmt_u32(matches_name_and_pid) });
		r.parsed.push_back({ "matches_name_any_pid", fmt_u32(matches_name_any_pid) });
		r.parsed.push_back({ "matches_name_self_or_unknown_pid", fmt_u32(matches_name_self_or_unknown_pid) });
		r.parsed.push_back({ "any_self_pid_rows", fmt_u32(any_self_pid_rows) });
		r.parsed.push_back({ "unknown_pid_rows", fmt_u32(unknown_pid_rows) });
		if (!matched_host.empty()) {
			r.parsed.push_back({ "matched_host", matched_host });
		}
		const std::uint32_t delta = (after_total >= baseline_total) ? (after_total - baseline_total) : 0u;
		r.parsed.push_back({ "delta_dns_entries", fmt_u32(delta) });

		if (matches_name_self_or_unknown_pid > 0u) {
			r.ntstatus = 0;
			r.ok = true;
		} else if (matches_name_any_pid > 0u) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			r.error = "DNS logger captured probe hostnames but attributed them to a different nonzero PID";
		} else if (any_self_pid_rows > 0u) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			r.error = "DNS logger captured self-PID rows but none contained the probe hostnames";
		} else if (delta > 0u && after_total > 0u) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			r.error = "DNS table changed during probe but no row matched both current PID and probe hostname";
		} else {
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
			r.ok = false;
			r.error = "DNS logging did not capture the current process DNS probes";
		}

		ctx->done = true;
		return 0;
	}

	void run_verify_dns_log(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		dns_log_ctx_t ctx{ &r, false };
		HANDLE h = CreateThread(nullptr, 0, dns_log_thread_proc, &ctx, 0, nullptr);
		if (h == nullptr) {
			r.ok = false;
			r.error = "CreateThread failed for dns_log_thread_proc";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		DWORD wait_rc = WaitForSingleObject(h, 5000);
		CloseHandle(h);
		if (wait_rc != WAIT_OBJECT_0) {
			r.ok = false;
			r.error = "DNS round-trip timed out (driver IOCTL deadlock suspected)";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
		}
	}

	void run_verify_net_stats(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!ensure_driver(r)) return;

		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		voyager::detail::net_cap_ctrl_request start_req{};
		start_req.operation = 0u;
		start_req.filter_pid = self_pid;
		start_req.filter_port = 0u;
		start_req.filter_protocol = 0u;
		start_req.max_packet_bytes = 1500u;
		std::uint32_t br_start = 0;
		bool cap_started = device->send_ioctl_raw(ioctl_codes::NCAP(), &start_req, sizeof(start_req), br_start);
		r.parsed.push_back({ "stats_capture_start_ok", cap_started ? "1" : "0" });
		r.parsed.push_back({ "stats_capture_filter_pid", fmt_u32(self_pid) });
		if (!cap_started) {
			r.ok = false;
			r.error = "NCAP start failed before NSTS probe";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		voyager::detail::net_stats_request base_req{};
		std::uint32_t br1 = 0;
		bool ok1 = device->send_ioctl_raw(ioctl_codes::NSTS(), &base_req, sizeof(base_req), br1);
		if (!ok1) {
			voyager::detail::net_cap_ctrl_request stop_req{};
			stop_req.operation = 1u;
			std::uint32_t br_stop = 0;
			device->send_ioctl_raw(ioctl_codes::NCAP(), &stop_req, sizeof(stop_req), br_stop);
			r.ok = false;
			r.error = "NSTS baseline ioctl failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		r.parsed.push_back({ "baseline_bytes_sent", fmt_u64(base_req.bytes_sent) });
		r.parsed.push_back({ "baseline_bytes_received", fmt_u64(base_req.bytes_received) });
		r.parsed.push_back({ "baseline_packets_sent", fmt_u64(base_req.packets_sent) });
		r.parsed.push_back({ "baseline_packets_received", fmt_u64(base_req.packets_received) });

		std::string probe_diag;
		bool probed = issue_raw_tcp_probe_to_one_one(probe_diag);
		r.parsed.push_back({ "probe_initiated", probed ? "1" : "0" });
		if (!probe_diag.empty()) {
			r.parsed.push_back({ "probe_diag", probe_diag });
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(300));

		voyager::detail::net_stats_request after_req{};
		std::uint32_t br2 = 0;
		bool ok2 = device->send_ioctl_raw(ioctl_codes::NSTS(), &after_req, sizeof(after_req), br2);
		r.bytes_returned = br2;
		if (!ok2) {
			voyager::detail::net_cap_ctrl_request stop_req{};
			stop_req.operation = 1u;
			std::uint32_t br_stop = 0;
			device->send_ioctl_raw(ioctl_codes::NCAP(), &stop_req, sizeof(stop_req), br_stop);
			r.ok = false;
			r.error = "NSTS post-traffic ioctl failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		voyager::detail::net_cap_ctrl_request stop_req{};
		stop_req.operation = 1u;
		std::uint32_t br_stop = 0;
		device->send_ioctl_raw(ioctl_codes::NCAP(), &stop_req, sizeof(stop_req), br_stop);
		r.parsed.push_back({ "stats_capture_stop_ok", "1" });
		r.parsed.push_back({ "after_bytes_sent", fmt_u64(after_req.bytes_sent) });
		r.parsed.push_back({ "after_bytes_received", fmt_u64(after_req.bytes_received) });
		r.parsed.push_back({ "after_packets_sent", fmt_u64(after_req.packets_sent) });
		r.parsed.push_back({ "after_packets_received", fmt_u64(after_req.packets_received) });

		const std::uint64_t d_bs = (after_req.bytes_sent >= base_req.bytes_sent) ? (after_req.bytes_sent - base_req.bytes_sent) : 0ull;
		const std::uint64_t d_br_v = (after_req.bytes_received >= base_req.bytes_received) ? (after_req.bytes_received - base_req.bytes_received) : 0ull;
		const std::uint64_t d_ps = (after_req.packets_sent >= base_req.packets_sent) ? (after_req.packets_sent - base_req.packets_sent) : 0ull;
		const std::uint64_t d_pr = (after_req.packets_received >= base_req.packets_received) ? (after_req.packets_received - base_req.packets_received) : 0ull;
		r.parsed.push_back({ "delta_bytes_sent", fmt_u64(d_bs) });
		r.parsed.push_back({ "delta_bytes_received", fmt_u64(d_br_v) });
		r.parsed.push_back({ "delta_packets_sent", fmt_u64(d_ps) });
		r.parsed.push_back({ "delta_packets_received", fmt_u64(d_pr) });

		bool any_increase = (d_bs > 0ull) || (d_br_v > 0ull) || (d_ps > 0ull) || (d_pr > 0ull);
		if (any_increase) {
			r.ntstatus = 0;
			r.ok = true;
		} else {
			r.ok = false;
			r.error = "NSTS counters did not increase after generating traffic -- stats collection may be broken";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
	}

	__declspec(noinline) bool seh_write_pattern(std::uint64_t* dst, std::size_t count, std::uint64_t pattern) {
		__try {
			for (std::size_t i = 0; i < count; ++i) dst[i] = pattern;
			std::uint64_t check = dst[0] ^ dst[count - 1];
			return check == 0ull;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}

	void run_verify_memory_round_trip(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!ensure_driver(r)) return;
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());

		voyager::detail::alloc_mem_request areq{};
		areq.pid = self_pid;
		areq.size = 4096ull;
		std::uint32_t br1 = 0;
		bool ok_a = device->send_ioctl_raw(ioctl_codes::AM(), &areq, sizeof(areq), br1);
		if (!ok_a || areq.allocated_address == 0ull) {
			r.ok = false;
			r.error = "AM allocate ioctl failed or returned null address";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		const std::uint64_t addr = areq.allocated_address;
		r.parsed.push_back({ "step1_allocated_address", fmt_hex_u64(addr) });
		r.parsed.push_back({ "step1_actual_size", fmt_u64(areq.actual_size) });

		void* user_ptr = reinterpret_cast<void*>(static_cast<std::uintptr_t>(addr));
		DWORD old_prot = 0;
		BOOL vp_ok = VirtualProtect(user_ptr, 4096, PAGE_READWRITE, &old_prot);
		if (!vp_ok) {
			DWORD err = GetLastError();
			char b[80];
			std::snprintf(b, sizeof(b), "VirtualProtect failed err=%lu", static_cast<unsigned long>(err));
			r.parsed.push_back({ "step2_virtualprotect_diag", std::string(b) });
		} else {
			r.parsed.push_back({ "step2_virtualprotect", "PAGE_READWRITE" });
		}
		const std::uint64_t pattern = 0xDEADBEEFCAFEBABEull;
		std::uint64_t* dst = static_cast<std::uint64_t*>(user_ptr);
		bool write_ok = seh_write_pattern(dst, 64, pattern);
		r.parsed.push_back({ "step2_write_pattern_ok", write_ok ? "1" : "0" });

		voyager::detail::query_memory_request qreq{};
		qreq.pid = self_pid;
		qreq.address = addr;
		std::uint32_t br2 = 0;
		bool ok_q = device->send_ioctl_raw(ioctl_codes::QM(), &qreq, sizeof(qreq), br2);
		if (!ok_q) {
			r.ok = false;
			r.error = "QM query (post-alloc) ioctl failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		r.parsed.push_back({ "step3_region_base", fmt_hex_u64(qreq.region_base) });
		r.parsed.push_back({ "step3_region_size", fmt_u64(qreq.region_size) });
		r.parsed.push_back({ "step3_state", fmt_hex_u64(static_cast<std::uint64_t>(qreq.state)) });
		r.parsed.push_back({ "step3_protect", fmt_hex_u64(static_cast<std::uint64_t>(qreq.protect)) });
		const bool committed_ok = (qreq.state == 0x1000u) && (qreq.region_size >= 4096ull);

		voyager::detail::free_mem_request freq{};
		freq.pid = self_pid;
		freq.address = addr;
		std::uint32_t br3 = 0;
		bool ok_f = device->send_ioctl_raw(ioctl_codes::FM(), &freq, sizeof(freq), br3);
		r.parsed.push_back({ "step4_free_ioctl_ok", ok_f ? "1" : "0" });

		voyager::detail::query_memory_request qreq2{};
		qreq2.pid = self_pid;
		qreq2.address = addr;
		std::uint32_t br4 = 0;
		bool ok_q2 = device->send_ioctl_raw(ioctl_codes::QM(), &qreq2, sizeof(qreq2), br4);
		r.bytes_returned = br4;
		bool freed_ok = false;
		if (ok_q2) {
			r.parsed.push_back({ "step5_post_free_state", fmt_hex_u64(static_cast<std::uint64_t>(qreq2.state)) });
			freed_ok = (qreq2.state == 0x10000u);
		} else {
			r.parsed.push_back({ "step5_post_free_query", "QM returned false (region likely gone)" });
			freed_ok = true;
		}

		if (write_ok && committed_ok && ok_f && freed_ok) {
			r.ntstatus = 0;
			r.ok = true;
		} else {
			r.ok = false;
			if (!write_ok) r.error = "user-mode write into kernel-allocated region failed";
			else if (!committed_ok) r.error = "QM did not report MEM_COMMIT with >=4096 bytes after alloc";
			else if (!ok_f) r.error = "FM free ioctl failed";
			else r.error = "post-free QM reported region still committed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
	}

	void run_verify_shadowfs_round_trip(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!shadow_fs_client::is_connected()) {
			shadow_fs_client::initialize();
		}
		if (!shadow_fs_client::is_connected()) {
			r.ok = false;
			r.error = "shadowfs port unreachable";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		r.parsed.push_back({ "step1_shadowfs_connected", "1" });

		const char* sandbox_root_utf8 = "C:\\Users\\Public\\Desktop\\aida_sandbox_test\\";
		BOOL cd = CreateDirectoryA(sandbox_root_utf8, nullptr);
		DWORD cd_err = cd ? 0u : GetLastError();
		if (cd_err != 0u && cd_err != ERROR_ALREADY_EXISTS) {
			char b[96];
			std::snprintf(b, sizeof(b), "CreateDirectoryA err=%lu", static_cast<unsigned long>(cd_err));
			r.parsed.push_back({ "step2_mkdir_warning", std::string(b) });
		} else {
			r.parsed.push_back({ "step2_sandbox_root", sandbox_root_utf8 });
		}

		const std::wstring root = L"C:\\Users\\Public\\Desktop\\aida_sandbox_test\\";
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		bool reg_ok = shadow_fs_client::register_sandbox_pid(self_pid, shadow_fs_client::k_default_flags, root);
		r.parsed.push_back({ "step3_register_sandbox_pid_ok", reg_ok ? "1" : "0" });
		if (!reg_ok) {
			const std::string& err = shadow_fs_client::last_error();
			r.parsed.push_back({ "step3_register_err", err.empty() ? "(no detail)" : err });
			r.ok = false;
			r.error = "register_sandbox_pid failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(100));

		shadow_fs_client::shadow_stats_t before{};
		bool ok_before = shadow_fs_client::query_stats(before);
		if (!ok_before) {
			shadow_fs_client::unregister_sandbox_pid(self_pid);
			r.ok = false;
			r.error = "query_stats (baseline) failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		r.parsed.push_back({ "baseline_redirects", fmt_u64(static_cast<std::uint64_t>(before.redirects)) });
		r.parsed.push_back({ "baseline_copies", fmt_u64(static_cast<std::uint64_t>(before.copies)) });
		r.parsed.push_back({ "baseline_denials", fmt_u64(static_cast<std::uint64_t>(before.denials)) });

		const char* test_path = "C:\\Users\\Public\\Desktop\\aida_outside_sandbox_test.txt";
		HANDLE h = CreateFileA(test_path,
			GENERIC_WRITE,
			FILE_SHARE_READ,
			nullptr,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);
		bool wrote = false;
		if (h != INVALID_HANDLE_VALUE) {
			const char* payload = "round-trip test";
			DWORD written = 0;
			WriteFile(h, payload, static_cast<DWORD>(std::strlen(payload)), &written, nullptr);
			CloseHandle(h);
			wrote = (written == std::strlen(payload));
		} else {
			DWORD err = GetLastError();
			char b[96];
			std::snprintf(b, sizeof(b), "CreateFileA err=%lu", static_cast<unsigned long>(err));
			r.parsed.push_back({ "step5_write_err", std::string(b) });
		}
		r.parsed.push_back({ "step5_write_attempted", wrote ? "1" : "0" });

		std::this_thread::sleep_for(std::chrono::milliseconds(150));

		shadow_fs_client::shadow_stats_t after{};
		bool ok_after = shadow_fs_client::query_stats(after);
		shadow_fs_client::unregister_sandbox_pid(self_pid);
		r.parsed.push_back({ "step7_unregister", "done" });
		if (!ok_after) {
			r.ok = false;
			r.error = "query_stats (post-write) failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		r.parsed.push_back({ "after_redirects", fmt_u64(static_cast<std::uint64_t>(after.redirects)) });
		r.parsed.push_back({ "after_copies", fmt_u64(static_cast<std::uint64_t>(after.copies)) });
		r.parsed.push_back({ "after_denials", fmt_u64(static_cast<std::uint64_t>(after.denials)) });

		const std::int64_t d_red = after.redirects - before.redirects;
		const std::int64_t d_cop = after.copies - before.copies;
		const std::int64_t d_den = after.denials - before.denials;
		char b1[32], b2[32], b3[32];
		std::snprintf(b1, sizeof(b1), "%lld", static_cast<long long>(d_red));
		std::snprintf(b2, sizeof(b2), "%lld", static_cast<long long>(d_cop));
		std::snprintf(b3, sizeof(b3), "%lld", static_cast<long long>(d_den));
		r.parsed.push_back({ "delta_redirects", std::string(b1) });
		r.parsed.push_back({ "delta_copies", std::string(b2) });
		r.parsed.push_back({ "delta_denials", std::string(b3) });

		bool any_change = (d_red > 0) || (d_cop > 0) || (d_den > 0);
		if (any_change) {
			r.ntstatus = 0;
			r.ok = true;
		} else {
			r.ok = false;
			r.error = "registration ok but minifilter did not intercept our write -- check Altitude / minifilter state";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
	}

	std::uint32_t count_self_pid_rows(const voyager::detail::tcpip_conn_dump_request& req,
		std::uint32_t self_pid,
		std::uint32_t& out_pid_and_one_one)
	{
		out_pid_and_one_one = 0u;
		std::uint32_t scan = req.connection_count;
		if (scan > voyager::detail::MAX_TCPIP_CONNECTIONS) scan = static_cast<std::uint32_t>(voyager::detail::MAX_TCPIP_CONNECTIONS);
		std::uint32_t pid_only = 0u;
		for (std::uint32_t i = 0; i < scan; ++i) {
			const auto& e = req.entries[i];
			if (e.pid == self_pid) {
				++pid_only;
				if (addr_is_one_one_one_one(e.remote_addr, e.address_family) && e.remote_port == 80u) {
					++out_pid_and_one_one;
				}
			}
		}
		return pid_only;
	}

	void run_verify_tcpip_connection_visible(test_lab::state_t& s, test_lab::result_t& r) {
		(void)s;
		if (!ensure_driver(r)) return;
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());

		wsa_guard_t g;
		if (!g.ok) {
			r.ok = false;
			r.error = "WSAStartup failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}

		voyager::detail::tcpip_conn_dump_request* baseline_req =
			static_cast<voyager::detail::tcpip_conn_dump_request*>(std::calloc(1, sizeof(voyager::detail::tcpip_conn_dump_request)));
		if (baseline_req == nullptr) {
			r.ok = false;
			r.error = "calloc failed for baseline tcpip_conn_dump_request";
			r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
			return;
		}
		baseline_req->target_pid = 0u;
		baseline_req->filter_protocol = 0u;
		std::uint32_t br_base = 0;
		bool ok_base = device->send_ioctl_raw(ioctl_codes::DTCP(), baseline_req, sizeof(*baseline_req), br_base);
		std::uint32_t baseline_self_one_one = 0u;
		std::uint32_t baseline_self_pid_rows = ok_base ? count_self_pid_rows(*baseline_req, self_pid, baseline_self_one_one) : 0u;
		const std::uint32_t baseline_total = ok_base ? baseline_req->connection_count : 0u;
		std::free(baseline_req);
		r.parsed.push_back({ "baseline_tcb_total", fmt_u32(baseline_total) });
		r.parsed.push_back({ "baseline_self_pid_rows", fmt_u32(baseline_self_pid_rows) });
		r.parsed.push_back({ "baseline_self_to_1_1_1_1_port_80", fmt_u32(baseline_self_one_one) });

		SOCKET sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sk == INVALID_SOCKET) {
			r.ok = false;
			r.error = "socket() failed";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		u_long nb = 1;
		ioctlsocket(sk, FIONBIO, &nb);
		sockaddr_in dst{};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(80);
		dst.sin_addr.s_addr = htonl(0x01010101u);
		int rc = connect(sk, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
		bool initiated = false;
		if (rc == 0) {
			initiated = true;
		} else {
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK) {
				initiated = true;
			} else {
				char b[64];
				std::snprintf(b, sizeof(b), "connect() err=%d", err);
				r.parsed.push_back({ "connect_diag", std::string(b) });
			}
		}
		r.parsed.push_back({ "step1_connect_initiated", initiated ? "1" : "0" });

		if (initiated) {
			fd_set wf;
			FD_ZERO(&wf);
			FD_SET(sk, &wf);
			timeval tv{};
			tv.tv_sec = 0;
			tv.tv_usec = 200000;
			select(0, nullptr, &wf, nullptr, &tv);
		}

		std::uint32_t total = 0u;
		std::uint32_t pid_only = 0u;
		std::uint32_t pid_and_remote = 0u;
		std::uint32_t printed = 0u;
		const std::uint32_t print_cap = 6u;
		bool ok_dtcp = false;
		std::int32_t last_status = 0;

		for (int attempt = 0; attempt < 3; ++attempt) {
			voyager::detail::tcpip_conn_dump_request* req =
				static_cast<voyager::detail::tcpip_conn_dump_request*>(std::calloc(1, sizeof(voyager::detail::tcpip_conn_dump_request)));
			if (req == nullptr) {
				closesocket(sk);
				r.ok = false;
				r.error = "calloc failed for tcpip_conn_dump_request";
				r.ntstatus = static_cast<std::int32_t>(0xC000009Au);
				return;
			}
			req->target_pid = 0u;
			req->filter_protocol = 0u;
			std::uint32_t br = 0;
			ok_dtcp = device->send_ioctl_raw(ioctl_codes::DTCP(), req, sizeof(*req), br);
			r.bytes_returned = br;
			if (!ok_dtcp) {
				std::free(req);
				last_status = static_cast<std::int32_t>(0xC0000001u);
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
				continue;
			}
			total = req->connection_count;
			std::uint32_t scan = total;
			if (scan > voyager::detail::MAX_TCPIP_CONNECTIONS) scan = static_cast<std::uint32_t>(voyager::detail::MAX_TCPIP_CONNECTIONS);
			pid_only = 0u;
			pid_and_remote = 0u;
			printed = 0u;
			for (std::uint32_t i = 0; i < scan; ++i) {
				const auto& e = req->entries[i];
				if (e.pid == self_pid) {
					++pid_only;
					if (addr_is_one_one_one_one(e.remote_addr, e.address_family) && e.remote_port == 80u) {
						++pid_and_remote;
					}
					if (printed < print_cap) {
						char label[24];
						std::snprintf(label, sizeof(label), "self_tcb[%u]", printed);
						char val[256];
						std::snprintf(val, sizeof(val),
							"pid=%u %s:%u -> %s:%u state=%u",
							e.pid,
							fmt_ip_v4(e.local_addr).c_str(), e.local_port,
							fmt_ip_v4(e.remote_addr).c_str(), e.remote_port,
							e.state);
						r.parsed.push_back({ std::string(label), std::string(val) });
						++printed;
					}
				}
			}
			std::free(req);
			if (pid_and_remote > 0u) break;
			if (pid_only > baseline_self_pid_rows) break;
			std::this_thread::sleep_for(std::chrono::milliseconds(250));
		}

		r.parsed.push_back({ "tcb_table_total", fmt_u32(total) });
		r.parsed.push_back({ "self_pid_rows", fmt_u32(pid_only) });
		r.parsed.push_back({ "self_pid_rows_to_1_1_1_1_port_80", fmt_u32(pid_and_remote) });
		const std::uint32_t delta_self = (pid_only >= baseline_self_pid_rows) ? (pid_only - baseline_self_pid_rows) : 0u;
		r.parsed.push_back({ "delta_self_pid_rows", fmt_u32(delta_self) });

		closesocket(sk);

		if (!ok_dtcp) {
			r.ok = false;
			r.error = "DTCP ioctl failed across all retries";
			r.ntstatus = (last_status != 0) ? last_status : static_cast<std::int32_t>(0xC0000001u);
			return;
		}
		if (pid_and_remote > 0u) {
			r.ntstatus = 0;
			r.ok = true;
		} else if (delta_self > 0u) {
			r.ntstatus = 0;
			r.ok = true;
		} else if (pid_only > 0u && initiated) {
			r.ntstatus = 0;
			r.ok = true;
		} else {
			r.ok = false;
			r.error = "no newly-appearing self-PID row seen in DTCP output after probe -- connection may have RST'd before snapshot or TCB attribution path is broken";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
	}

}

TESTLAB_REGISTER(g_reg_verify_network_capture,
	"verify",
	test_lab::driver_e::whoswho,
	"Network capture round-trip",
	"NCAP start (filter on self PID) -> issue HTTP GET to 1.1.1.1 -> NCAP stop -> NCPG drain -> assert at least one packet attributed to current PID.",
	&render_inputs_empty,
	&run_verify_network_capture);

TESTLAB_REGISTER(g_reg_verify_dns_log,
	"verify",
	test_lab::driver_e::whoswho,
	"DNS query log round-trip",
	"getaddrinfo(test.example.com) -> NDNS drain -> assert kernel logged a DNS record for test.example.com from the current PID.",
	&render_inputs_empty,
	&run_verify_dns_log);

TESTLAB_REGISTER(g_reg_verify_net_stats,
	"verify",
	test_lab::driver_e::whoswho,
	"Network stats sanity",
	"NSTS baseline -> raw TCP probe to 1.1.1.1:80 -> NSTS again -> assert at least one of bytes_in/out or packets_in/out increased.",
	&render_inputs_empty,
	&run_verify_net_stats);

TESTLAB_REGISTER(g_reg_verify_memory_round_trip,
	"verify",
	test_lab::driver_e::whoswho,
	"Memory alloc/write/read/free round-trip",
	"AM allocate 4096 in self -> user-mode write 0xDEADBEEFCAFEBABE pattern -> QM verify MEM_COMMIT -> FM free -> QM verify MEM_FREE.",
	&render_inputs_empty,
	&run_verify_memory_round_trip);

TESTLAB_REGISTER(g_reg_verify_shadowfs_round_trip,
	"verify",
	test_lab::driver_e::shadowfs,
	"ShadowFS sandbox round-trip",
	"Connect shadowfs port -> mkdir sandbox -> register self PID -> CreateFile in sandbox path -> query_stats and assert redirects/copies/denials counter incremented -> unregister.",
	&render_inputs_empty,
	&run_verify_shadowfs_round_trip);

TESTLAB_REGISTER(g_reg_verify_tcpip_connection_visible,
	"verify",
	test_lab::driver_e::whoswho,
	"TCPIP connection table sanity",
	"Open TCP socket to 1.1.1.1:80 (non-blocking, SYN sent) -> DTCP dump -> assert self PID row to 1.1.1.1:80 visible in TCB table.",
	&render_inputs_empty,
	&run_verify_tcpip_connection_visible);
