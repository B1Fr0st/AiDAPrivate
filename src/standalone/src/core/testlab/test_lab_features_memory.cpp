#include "test_lab.hpp"
#include "test_lab_format.hpp"
#include "../../../../driver/comm.h"
#include "imgui/imgui.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {

	struct sdf_probe_t {
		HANDLE process = nullptr;
		std::uint64_t peb = 0;
		std::uint8_t before_being_debugged = 0;
		std::uint32_t before_nt_global_flag = 0;
		std::uint8_t after_being_debugged = 0;
		std::uint32_t after_nt_global_flag = 0;
		bool opened = false;
		bool queried = false;
		bool read_before = false;
		bool wrote_seed = false;
		bool read_after = false;
		bool restored = false;
		DWORD error = ERROR_SUCCESS;
	};

	struct sdf_process_basic_info_t {
		PVOID reserved1 = nullptr;
		PVOID peb_base_address = nullptr;
		PVOID reserved2[2]{};
		ULONG_PTR unique_process_id = 0;
		PVOID reserved3 = nullptr;
	};

	using nt_query_information_process_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

	bool ensure_driver(test_lab::result_t& r) {
		if (!device || !device->is_connected()) {
			r.ok = false;
			r.error = "driver not connected";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
			return false;
		}
		return true;
	}

	void set_fail_from_ioctl(test_lab::result_t& r, std::uint32_t bytes_returned) {
		r.ok = false;
		r.bytes_returned = bytes_returned;
		if (r.error.empty()) {
			r.error = "send_ioctl_raw returned false";
		}
		if (r.ntstatus == 0) {
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
		}
	}

	std::string format_hex_u64(std::uint64_t v) {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "0x%016llX", static_cast<unsigned long long>(v));
		return std::string(buf);
	}

	std::string format_hex_u32(std::uint32_t v) {
		char buf[16];
		std::snprintf(buf, sizeof(buf), "0x%08X", v);
		return std::string(buf);
	}

	bool seed_sdf_probe(std::uint32_t pid, sdf_probe_t& probe) {
		probe.process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
		if (!probe.process) {
			probe.error = GetLastError();
			return false;
		}
		probe.opened = true;
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		auto query = ntdll ? reinterpret_cast<nt_query_information_process_t>(GetProcAddress(ntdll, "NtQueryInformationProcess")) : nullptr;
		if (!query) {
			probe.error = GetLastError();
			return false;
		}
		sdf_process_basic_info_t pbi{};
		LONG status = query(probe.process, 0, &pbi, static_cast<ULONG>(sizeof(pbi)), nullptr);
		if (status < 0 || !pbi.peb_base_address) {
			probe.error = static_cast<DWORD>(status);
			return false;
		}
		probe.queried = true;
		probe.peb = reinterpret_cast<std::uint64_t>(pbi.peb_base_address);
		SIZE_T read_a = 0;
		SIZE_T read_b = 0;
		if (!ReadProcessMemory(probe.process, reinterpret_cast<LPCVOID>(probe.peb + 0x02), &probe.before_being_debugged, sizeof(probe.before_being_debugged), &read_a) ||
			read_a != sizeof(probe.before_being_debugged) ||
			!ReadProcessMemory(probe.process, reinterpret_cast<LPCVOID>(probe.peb + 0xBC), &probe.before_nt_global_flag, sizeof(probe.before_nt_global_flag), &read_b) ||
			read_b != sizeof(probe.before_nt_global_flag)) {
			probe.error = GetLastError();
			return false;
		}
		probe.read_before = true;
		const std::uint8_t seeded_debugged = static_cast<std::uint8_t>(probe.before_being_debugged | 0x1u);
		const std::uint32_t seeded_global = probe.before_nt_global_flag | 0x70u;
		SIZE_T wrote_a = 0;
		SIZE_T wrote_b = 0;
		if (!WriteProcessMemory(probe.process, reinterpret_cast<LPVOID>(probe.peb + 0x02), &seeded_debugged, sizeof(seeded_debugged), &wrote_a) ||
			wrote_a != sizeof(seeded_debugged) ||
			!WriteProcessMemory(probe.process, reinterpret_cast<LPVOID>(probe.peb + 0xBC), &seeded_global, sizeof(seeded_global), &wrote_b) ||
			wrote_b != sizeof(seeded_global)) {
			probe.error = GetLastError();
			return false;
		}
		probe.wrote_seed = true;
		return true;
	}

	void finish_sdf_probe(sdf_probe_t& probe) {
		if (!probe.process)
			return;
		if (probe.peb != 0) {
			SIZE_T read_a = 0;
			SIZE_T read_b = 0;
			probe.read_after =
				ReadProcessMemory(probe.process, reinterpret_cast<LPCVOID>(probe.peb + 0x02), &probe.after_being_debugged, sizeof(probe.after_being_debugged), &read_a) &&
				read_a == sizeof(probe.after_being_debugged) &&
				ReadProcessMemory(probe.process, reinterpret_cast<LPCVOID>(probe.peb + 0xBC), &probe.after_nt_global_flag, sizeof(probe.after_nt_global_flag), &read_b) &&
				read_b == sizeof(probe.after_nt_global_flag);
			if (!probe.read_after && probe.error == ERROR_SUCCESS)
				probe.error = GetLastError();
			if (probe.read_before) {
				SIZE_T wrote_a = 0;
				SIZE_T wrote_b = 0;
				probe.restored =
					WriteProcessMemory(probe.process, reinterpret_cast<LPVOID>(probe.peb + 0x02), &probe.before_being_debugged, sizeof(probe.before_being_debugged), &wrote_a) &&
					wrote_a == sizeof(probe.before_being_debugged) &&
					WriteProcessMemory(probe.process, reinterpret_cast<LPVOID>(probe.peb + 0xBC), &probe.before_nt_global_flag, sizeof(probe.before_nt_global_flag), &wrote_b) &&
					wrote_b == sizeof(probe.before_nt_global_flag);
				if (!probe.restored && probe.error == ERROR_SUCCESS)
					probe.error = GetLastError();
			}
		}
		CloseHandle(probe.process);
		probe.process = nullptr;
	}

	std::string format_dec_u64(std::uint64_t v) {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(v));
		return std::string(buf);
	}

	std::string mbi_state_name(std::uint32_t st) {
		switch (st) {
			case 0x1000u: return "MEM_COMMIT";
			case 0x2000u: return "MEM_RESERVE";
			case 0x10000u: return "MEM_FREE";
			default: return format_hex_u32(st);
		}
	}

	std::string mbi_type_name(std::uint32_t t) {
		switch (t) {
			case 0x20000u: return "MEM_PRIVATE";
			case 0x40000u: return "MEM_MAPPED";
			case 0x1000000u: return "MEM_IMAGE";
			default: return format_hex_u32(t);
		}
	}

	std::string mbi_protect_name(std::uint32_t p) {
		if (p == 0) return "(none)";
		switch (p & 0xFFu) {
			case 0x01u: return "PAGE_NOACCESS";
			case 0x02u: return "PAGE_READONLY";
			case 0x04u: return "PAGE_READWRITE";
			case 0x08u: return "PAGE_WRITECOPY";
			case 0x10u: return "PAGE_EXECUTE";
			case 0x20u: return "PAGE_EXECUTE_READ";
			case 0x40u: return "PAGE_EXECUTE_READWRITE";
			case 0x80u: return "PAGE_EXECUTE_WRITECOPY";
			default: return format_hex_u32(p);
		}
	}

	void capture_raw_struct(test_lab::result_t& r, const void* ptr, std::size_t sz) {
		r.raw.resize(sz);
		std::memcpy(r.raw.data(), ptr, sz);
	}

	void render_inputs_dtb(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Resolves CR3 (DirectoryTableBase) for the given process.");
	}

	void run_dtb(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		if (s.pid == 0) { r.error = "pid must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		voyager::detail::dtb_solve req{};
		req.pid = s.pid;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::DTB(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		r.parsed.push_back({ "PID", format_dec_u64(s.pid) });
		r.parsed.push_back({ "CR3 (DTB)", format_hex_u64(req.dtb) });
		r.ntstatus = 0;
		r.ok = (req.dtb != 0);
		if (!r.ok && r.error.empty()) {
			r.error = "kernel returned dtb=0";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
	}

	void render_inputs_phys(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("DTB (CR3, u64_a)", ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::InputScalar("Virtual address", ImGuiDataType_U64, &s.addr, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::InputScalar("Size (bytes, capped 4096)", ImGuiDataType_U32, &s.size, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Reads memory via VA->phys translation using the provided DTB.");
	}

	void run_phys(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		if (s.u64_a == 0) { r.error = "dtb must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		if (s.addr == 0) { r.error = "address must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC0000022u); r.ok = false; return; }
		std::uint32_t sz = s.size;
		if (sz == 0) sz = 256;
		if (sz > 4096) sz = 4096;
		std::vector<std::uint8_t> buf(sz, 0);
		voyager::detail::physical_request req{};
		req.pid = s.pid;
		req.dtb = s.u64_a;
		req.address = reinterpret_cast<void*>(static_cast<std::uintptr_t>(s.addr));
		req.buffer = buf.data();
		req.size = sz;
		req.ret_size = 0;
		req.should_write = 0;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::PHYS(), &req, sizeof(req), bytes_returned);
		r.bytes_returned = bytes_returned;
		if (!ok) {
			capture_raw_struct(r, &req, sizeof(req));
			set_fail_from_ioctl(r, bytes_returned);
			return;
		}
		r.raw = buf;
		r.parsed.push_back({ "PID", format_dec_u64(s.pid) });
		r.parsed.push_back({ "DTB", format_hex_u64(s.u64_a) });
		r.parsed.push_back({ "Address", format_hex_u64(s.addr) });
		r.parsed.push_back({ "Requested size", format_dec_u64(sz) });
		r.parsed.push_back({ "Bytes transferred", format_dec_u64(static_cast<std::uint64_t>(req.ret_size)) });
		r.ntstatus = 0;
		r.ok = (req.ret_size > 0);
		if (!r.ok && r.error.empty()) {
			r.error = "kernel returned zero bytes transferred";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
		}
	}

	void render_inputs_base(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		char mod_name[260];
		std::snprintf(mod_name, sizeof(mod_name), "%s", s.text_a.c_str());
		if (ImGui::InputText("Module name (informational)", mod_name, sizeof(mod_name))) {
			s.text_a = mod_name;
		}
		ImGui::TextDisabled("Returns PsGetProcessSectionBaseAddress for the PID. Module name is informational only (kernel returns the EXE base).");
	}

	void run_base(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		if (s.pid == 0) { r.error = "pid must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		auto out_holder = std::make_unique<std::uint64_t>(0);
		voyager::detail::base_address_request req{};
		req.pid = s.pid;
		req.out_address = out_holder.get();
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::BASE(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		r.parsed.push_back({ "PID", format_dec_u64(s.pid) });
		if (!s.text_a.empty()) {
			r.parsed.push_back({ "Requested module", s.text_a });
		}
		r.parsed.push_back({ "Image base", format_hex_u64(*out_holder) });
		r.ntstatus = 0;
		r.ok = (*out_holder != 0);
		if (!r.ok && r.error.empty()) {
			r.error = "kernel returned image_base=0";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
	}

	void render_inputs_am(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("Size (bytes)", ImGuiDataType_U32, &s.size, nullptr, nullptr, "%u");
		ImGui::InputScalar("Protect flags (informational, u32_a)", ImGuiDataType_U32, &s.u32_a, nullptr, nullptr, "0x%08X", ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::TextDisabled("Allocates page-aligned RWX memory in the target process. Kernel forces PAGE_EXECUTE_READWRITE; protect flag is informational.");
	}

	void run_am(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		if (s.pid <= 4) { r.error = "pid must be > 4"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		if (s.size == 0) { r.error = "size must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC0000206u); r.ok = false; return; }
		voyager::detail::alloc_mem_request req{};
		req.pid = s.pid;
		req.size = s.size;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::AM(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		r.parsed.push_back({ "PID", format_dec_u64(s.pid) });
		r.parsed.push_back({ "Requested size", format_dec_u64(s.size) });
		r.parsed.push_back({ "Requested protect", format_hex_u32(s.u32_a) });
		r.parsed.push_back({ "Allocated address", format_hex_u64(req.allocated_address) });
		r.parsed.push_back({ "Actual size", format_dec_u64(req.actual_size) });
		r.ntstatus = 0;
		r.ok = (req.allocated_address != 0);
		if (!r.ok && r.error.empty()) {
			r.error = "allocation returned address=0";
			r.ntstatus = static_cast<std::int32_t>(0xC0000017u);
		}
	}

	void render_inputs_fm(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("Address", ImGuiDataType_U64, &s.addr, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::InputScalar("Size (informational)", ImGuiDataType_U32, &s.size, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Frees the entire reserved region at the given address (MEM_RELEASE). Size is informational only.");
	}

	void run_fm(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		if (s.pid <= 4) { r.error = "pid must be > 4"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		if (s.addr == 0) { r.error = "address must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		voyager::detail::free_mem_request req{};
		req.pid = s.pid;
		req.address = s.addr;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::FM(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		r.parsed.push_back({ "PID", format_dec_u64(s.pid) });
		r.parsed.push_back({ "Address", format_hex_u64(s.addr) });
		r.parsed.push_back({ "Requested size", format_dec_u64(s.size) });
		r.parsed.push_back({ "Result", "freed" });
		r.ntstatus = 0;
		r.ok = true;
	}

	void render_inputs_qm(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("Address", ImGuiDataType_U64, &s.addr, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::TextDisabled("ZwQueryVirtualMemory(MemoryBasicInformation) on the target process.");
	}

	void run_qm(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		if (s.pid == 0) { r.error = "pid must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		voyager::detail::query_memory_request req{};
		req.pid = s.pid;
		req.address = s.addr;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::QM(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		r.parsed.push_back({ "PID", format_dec_u64(s.pid) });
		r.parsed.push_back({ "Query address", format_hex_u64(s.addr) });
		r.parsed.push_back({ "Region base", format_hex_u64(req.region_base) });
		r.parsed.push_back({ "Region size", format_dec_u64(req.region_size) });
		r.parsed.push_back({ "State", mbi_state_name(req.state) });
		r.parsed.push_back({ "Protect", mbi_protect_name(req.protect) });
		r.parsed.push_back({ "Type", mbi_type_name(req.type) });
		r.parsed.push_back({ "Allocation base", format_hex_u64(req.allocation_base) });
		r.parsed.push_back({ "Allocation protect", mbi_protect_name(req.allocation_protect) });
		r.ntstatus = 0;
		r.ok = true;
	}

	void render_inputs_pm(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("Address", ImGuiDataType_U64, &s.addr, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::InputScalar("Size (bytes)", ImGuiDataType_U32, &s.size, nullptr, nullptr, "%u");
		ImGui::InputScalar("New protect (u32_a)", ImGuiDataType_U32, &s.u32_a, nullptr, nullptr, "0x%08X", ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::TextDisabled("Calls ZwProtectVirtualMemory on the target process. Typical protect: 0x20=RX, 0x40=RWX, 0x04=RW, 0x02=R.");
	}

	void run_pm(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		if (s.pid == 0) { r.error = "pid must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		if (s.size == 0) { r.error = "size must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }

		void* bootstrap_alloc = nullptr;
		std::uint64_t effective_addr = s.addr;
		const std::uint32_t self_pid = static_cast<std::uint32_t>(GetCurrentProcessId());
		if (s.pid == self_pid) {
			SIZE_T region_size = static_cast<SIZE_T>((s.size + 0xFFFu) & ~SIZE_T(0xFFFu));
			bootstrap_alloc = VirtualAlloc(nullptr, region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!bootstrap_alloc) {
				r.error = "bootstrap VirtualAlloc failed";
				r.ntstatus = static_cast<std::int32_t>(0xC0000017u);
				r.ok = false;
				return;
			}
			effective_addr = reinterpret_cast<std::uint64_t>(bootstrap_alloc);
		}

		voyager::detail::protect_memory_request req{};
		req.pid = s.pid;
		req.new_protect = s.u32_a;
		req.address = effective_addr;
		req.size = s.size;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::PM(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		if (bootstrap_alloc) {
			VirtualFree(bootstrap_alloc, 0, MEM_RELEASE);
		}
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		r.parsed.push_back({ "PID", format_dec_u64(s.pid) });
		r.parsed.push_back({ "Address", format_hex_u64(effective_addr) });
		r.parsed.push_back({ "Size", format_dec_u64(s.size) });
		r.parsed.push_back({ "New protect", mbi_protect_name(s.u32_a) });
		r.parsed.push_back({ "Old protect", mbi_protect_name(req.old_protect) });
		if (bootstrap_alloc) {
			r.parsed.push_back({ "Bootstrap", "VirtualAlloc-then-free (self-pid)" });
		}
		r.ntstatus = 0;
		r.ok = true;
	}

	void render_inputs_er(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("Start address (0 = scan from 0)", ImGuiDataType_U64, &s.addr, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::InputScalar("Max address (0 = full user range)", ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
		bool include_all = (s.u32_a != 0);
		if (ImGui::Checkbox("Include all regions (not only MEM_COMMIT)", &include_all)) {
			s.u32_a = include_all ? 1u : 0u;
		}
		ImGui::TextDisabled("Enumerates committed memory regions for the target PID (up to 4096 entries).");
	}

	void run_er(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		if (s.pid == 0) { r.error = "pid must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		auto req = std::make_unique<voyager::detail::enum_regions_request>();
		std::memset(req.get(), 0, sizeof(*req));
		req->pid = s.pid;
		req->include_all = (s.u32_a != 0) ? 1u : 0u;
		req->start_address = s.addr;
		req->max_address = s.u64_a;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::ER(), req.get(), static_cast<std::uint32_t>(sizeof(*req)), bytes_returned);
		r.bytes_returned = bytes_returned;
		if (!ok) {
			capture_raw_struct(r, req.get(), 32);
			set_fail_from_ioctl(r, bytes_returned);
			return;
		}
		std::uint32_t count = req->region_count;
		if (count > voyager::detail::MAX_ENUM_REGIONS) count = voyager::detail::MAX_ENUM_REGIONS;
		std::size_t header_sz = 32;
		std::size_t entries_sz = static_cast<std::size_t>(count) * sizeof(voyager::detail::region_entry);
		r.raw.resize(header_sz + entries_sz);
		std::memcpy(r.raw.data(), req.get(), header_sz);
		if (entries_sz > 0) {
			std::memcpy(r.raw.data() + header_sz, req->entries, entries_sz);
		}
		r.parsed.push_back({ "PID", format_dec_u64(s.pid) });
		r.parsed.push_back({ "Region count", format_dec_u64(count) });
		std::uint32_t preview = count;
		if (preview > 16) preview = 16;
		for (std::uint32_t i = 0; i < preview; ++i) {
			const auto& e = req->entries[i];
			char label[32];
			std::snprintf(label, sizeof(label), "[%u] base", i);
			r.parsed.push_back({ label, format_hex_u64(e.base) });
			std::snprintf(label, sizeof(label), "[%u] size", i);
			r.parsed.push_back({ label, format_dec_u64(e.size) });
			std::snprintf(label, sizeof(label), "[%u] state/protect/type", i);
			std::string combo = mbi_state_name(e.state) + " / " + mbi_protect_name(e.protect) + " / " + mbi_type_name(e.type);
			r.parsed.push_back({ label, combo });
		}
		if (count > preview) {
			r.parsed.push_back({ "(truncated)", format_dec_u64(count - preview) + " more entries in raw buffer" });
		}
		r.ntstatus = 0;
		r.ok = true;
	}

	void render_inputs_rpeb(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::TextDisabled("Reads PEB fields: image_base, BeingDebugged, NtGlobalFlag, Ldr, ProcessHeap, NumberOfHeaps, ProcessHeaps.");
	}

	void run_rpeb(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		if (s.pid == 0) { r.error = "pid must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		voyager::detail::read_peb_request req{};
		req.pid = s.pid;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::RPEB(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		r.parsed.push_back({ "PID", format_dec_u64(s.pid) });
		r.parsed.push_back({ "PEB address", format_hex_u64(req.peb_address) });
		r.parsed.push_back({ "Image base", format_hex_u64(req.image_base) });
		r.parsed.push_back({ "BeingDebugged", format_dec_u64(req.being_debugged) });
		r.parsed.push_back({ "NtGlobalFlag", format_hex_u32(req.nt_global_flag) });
		r.parsed.push_back({ "Ldr", format_hex_u64(req.ldr_address) });
		r.parsed.push_back({ "ProcessHeap", format_hex_u64(req.process_heap) });
		r.parsed.push_back({ "NumberOfHeaps", format_dec_u64(req.number_of_heaps) });
		r.parsed.push_back({ "MaximumHeaps", format_dec_u64(req.max_heaps) });
		r.parsed.push_back({ "ProcessHeaps", format_hex_u64(req.process_heaps) });
		r.ntstatus = 0;
		r.ok = (req.peb_address != 0);
		if (!r.ok && r.error.empty()) {
			r.error = "kernel returned peb_address=0";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
	}

	void render_inputs_sdf(test_lab::state_t& s) {
		ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid, nullptr, nullptr, "%u");
		ImGui::InputScalar("Expected clear mask (u32_a, 0 = PEB bits)", ImGuiDataType_U32, &s.u32_a, nullptr, nullptr, "0x%08X", ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::TextDisabled("Clears EPROCESS.DebugPort, PEB.BeingDebugged, and the heap-debug bits in PEB.NtGlobalFlag. Kernel reports which fields it actually cleared.");
	}

	void run_sdf(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		if (s.pid == 0) { r.error = "pid must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		sdf_probe_t probe{};
		const bool seeded = seed_sdf_probe(s.pid, probe);
		voyager::detail::spoof_debug_request req{};
		req.pid = s.pid;
		req.result_flags = 0;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::SDF(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		finish_sdf_probe(probe);
		r.parsed.push_back({ "PID", format_dec_u64(s.pid) });
		r.parsed.push_back({ "PEB address", format_hex_u64(probe.peb) });
		r.parsed.push_back({ "Seed opened", seeded && probe.opened ? "1" : "0" });
		r.parsed.push_back({ "Seed queried", probe.queried ? "1" : "0" });
		r.parsed.push_back({ "Seed wrote debug bits", probe.wrote_seed ? "1" : "0" });
		r.parsed.push_back({ "Seed before BeingDebugged", format_hex_u32(probe.before_being_debugged) });
		r.parsed.push_back({ "Seed before NtGlobalFlag", format_hex_u32(probe.before_nt_global_flag) });
		r.parsed.push_back({ "Read after", probe.read_after ? "1" : "0" });
		r.parsed.push_back({ "After BeingDebugged", format_hex_u32(probe.after_being_debugged) });
		r.parsed.push_back({ "After NtGlobalFlag", format_hex_u32(probe.after_nt_global_flag) });
		r.parsed.push_back({ "Restored", probe.restored ? "1" : "0" });
		r.parsed.push_back({ "Probe error", format_hex_u32(probe.error) });
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		const std::uint32_t expected = s.u32_a != 0 ? s.u32_a : 0x6u;
		r.parsed.push_back({ "Expected clear mask", format_hex_u32(expected) });
		r.parsed.push_back({ "Result flags", format_hex_u32(req.result_flags) });
		std::string cleared;
		if (req.result_flags & 0x1u) cleared += "DebugPort ";
		if (req.result_flags & 0x2u) cleared += "PEB.BeingDebugged ";
		if (req.result_flags & 0x4u) cleared += "PEB.NtGlobalFlag ";
		if (cleared.empty()) cleared = "(none)";
		r.parsed.push_back({ "Cleared fields", cleared });
		r.ntstatus = 0;
		const bool expected_cleared = (req.result_flags & expected) == expected;
		const bool readback_cleared = probe.read_after &&
			((probe.after_being_debugged & 0x1u) == 0) &&
			((probe.after_nt_global_flag & 0x70u) == 0);
		r.ok = seeded && probe.wrote_seed && expected_cleared && readback_cleared && probe.restored;
		if (!r.ok) {
			r.error = "SDF did not prove seeded PEB debug bits were cleared and restored";
			r.ntstatus = static_cast<std::int32_t>(0xC0000001u);
		}
	}

	void render_inputs_mex(test_lab::state_t& s) {
		ImGui::InputScalar("DTB (CR3, u64_a)", ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::InputScalar("Module base (addr)", ImGuiDataType_U64, &s.addr, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
		char mod_buf[260];
		std::snprintf(mod_buf, sizeof(mod_buf), "%s", s.text_a.c_str());
		if (ImGui::InputText("Module name (informational)", mod_buf, sizeof(mod_buf))) {
			s.text_a = mod_buf;
		}
		char exp_buf[128];
		std::snprintf(exp_buf, sizeof(exp_buf), "%s", s.text_b.c_str());
		if (ImGui::InputText("Export name", exp_buf, sizeof(exp_buf))) {
			s.text_b = exp_buf;
		}
		ImGui::TextDisabled("Resolves an export by name within a PE image. Kernel needs DTB (use the DTB feature first) and module base address.");
	}

	void run_mex(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		if (s.u64_a == 0) { r.error = "dtb must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		if (s.addr == 0) { r.error = "module base must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		if (s.text_b.empty()) { r.error = "export name must not be empty"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		voyager::detail::module_export_request req{};
		req.dtb = s.u64_a;
		req.module_base = s.addr;
		std::size_t n = s.text_b.size();
		if (n > sizeof(req.export_name) - 1) n = sizeof(req.export_name) - 1;
		std::memcpy(req.export_name, s.text_b.data(), n);
		req.export_name[n] = '\0';
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::MEX(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		r.parsed.push_back({ "DTB", format_hex_u64(s.u64_a) });
		r.parsed.push_back({ "Module base", format_hex_u64(s.addr) });
		if (!s.text_a.empty()) {
			r.parsed.push_back({ "Module (hint)", s.text_a });
		}
		r.parsed.push_back({ "Export name", s.text_b });
		r.parsed.push_back({ "Resolved address", format_hex_u64(req.resolved_address) });
		r.parsed.push_back({ "Ordinal", format_dec_u64(req.ordinal) });
		r.ntstatus = 0;
		r.ok = (req.resolved_address != 0);
		if (!r.ok && r.error.empty()) {
			r.error = "export not found";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
	}

	void render_inputs_v2p(test_lab::state_t& s) {
		ImGui::InputScalar("DTB (CR3, u64_a)", ImGuiDataType_U64, &s.u64_a, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::InputScalar("Virtual address", ImGuiDataType_U64, &s.addr, nullptr, nullptr, "0x%016llX", ImGuiInputTextFlags_CharsHexadecimal);
		ImGui::TextDisabled("Walks the page tables for the given DTB and translates VA -> physical address.");
	}

	void run_v2p(test_lab::state_t& s, test_lab::result_t& r) {
		if (!ensure_driver(r)) return;
		if (s.u64_a == 0) { r.error = "dtb must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		if (s.addr == 0) { r.error = "virtual address must be non-zero"; r.ntstatus = static_cast<std::int32_t>(0xC000000Du); r.ok = false; return; }
		voyager::detail::virt_to_phys_request req{};
		req.dtb = s.u64_a;
		req.virtual_address = s.addr;
		std::uint32_t bytes_returned = 0;
		bool ok = device->send_ioctl_raw(ioctl_codes::V2P(), &req, sizeof(req), bytes_returned);
		capture_raw_struct(r, &req, sizeof(req));
		r.bytes_returned = bytes_returned;
		if (!ok) { set_fail_from_ioctl(r, bytes_returned); return; }
		r.parsed.push_back({ "DTB", format_hex_u64(s.u64_a) });
		r.parsed.push_back({ "Virtual address", format_hex_u64(s.addr) });
		r.parsed.push_back({ "Physical address", format_hex_u64(req.physical_address) });
		r.ntstatus = 0;
		r.ok = (req.physical_address != 0);
		if (!r.ok && r.error.empty()) {
			r.error = "translation returned physical=0";
			r.ntstatus = static_cast<std::int32_t>(0xC0000225u);
		}
	}

}

TESTLAB_REGISTER(g_reg_dtb_memory,
	"memory",
	test_lab::driver_e::whoswho,
	"DTB - solve DirectoryTableBase",
	"ioctl_codes::DTB() with dtb_solve{ pid }. Returns CR3 for the given PID.",
	&render_inputs_dtb,
	&run_dtb);

TESTLAB_REGISTER(g_reg_phys_memory,
	"memory",
	test_lab::driver_e::whoswho,
	"PHYS - read process memory via phys translation",
	"ioctl_codes::PHYS() with physical_request{ pid, dtb, address, buffer, size, should_write=0 }. Reads up to 4096 bytes.",
	&render_inputs_phys,
	&run_phys);

TESTLAB_REGISTER(g_reg_base_memory,
	"memory",
	test_lab::driver_e::whoswho,
	"BASE - get section base address by PID",
	"ioctl_codes::BASE() with base_address_request{ pid, out_address }. Returns PsGetProcessSectionBaseAddress().",
	&render_inputs_base,
	&run_base);

TESTLAB_REGISTER(g_reg_am_memory,
	"memory",
	test_lab::driver_e::whoswho,
	"AM - allocate memory in target process",
	"ioctl_codes::AM() with alloc_mem_request{ pid, size }. Kernel allocates page-aligned PAGE_EXECUTE_READWRITE.",
	&render_inputs_am,
	&run_am);

TESTLAB_REGISTER(g_reg_fm_memory,
	"memory",
	test_lab::driver_e::whoswho,
	"FM - free memory in target process",
	"ioctl_codes::FM() with free_mem_request{ pid, address }. MEM_RELEASE on the entire allocation.",
	&render_inputs_fm,
	&run_fm);

TESTLAB_REGISTER(g_reg_qm_memory,
	"memory",
	test_lab::driver_e::whoswho,
	"QM - query memory (MEMORY_BASIC_INFORMATION)",
	"ioctl_codes::QM() with query_memory_request{ pid, address }. Returns region base/size/state/protect/type.",
	&render_inputs_qm,
	&run_qm);

TESTLAB_REGISTER(g_reg_pm_memory,
	"memory",
	test_lab::driver_e::whoswho,
	"PM - protect memory in target process",
	"ioctl_codes::PM() with protect_memory_request{ pid, new_protect, address, size }. Returns old_protect.",
	&render_inputs_pm,
	&run_pm);

TESTLAB_REGISTER(g_reg_er_memory,
	"memory",
	test_lab::driver_e::whoswho,
	"ER - enumerate committed regions",
	"ioctl_codes::ER() with enum_regions_request{ pid, include_all, start_address, max_address }. Up to 4096 entries.",
	&render_inputs_er,
	&run_er);

TESTLAB_REGISTER(g_reg_rpeb_memory,
	"memory",
	test_lab::driver_e::whoswho,
	"RPEB - read remote PEB",
	"ioctl_codes::RPEB() with read_peb_request{ pid }. Returns PEB address, image_base, BeingDebugged, NtGlobalFlag, Ldr, heaps.",
	&render_inputs_rpeb,
	&run_rpeb);

TESTLAB_REGISTER(g_reg_sdf_memory,
	"memory",
	test_lab::driver_e::whoswho,
	"SDF - spoof debug flags",
	"ioctl_codes::SDF() with spoof_debug_request{ pid }. Clears DebugPort + PEB.BeingDebugged + PEB.NtGlobalFlag heap-debug bits.",
	&render_inputs_sdf,
	&run_sdf);

TESTLAB_REGISTER(g_reg_mex_memory,
	"memory",
	test_lab::driver_e::whoswho,
	"MEX - resolve module export address",
	"ioctl_codes::MEX() with module_export_request{ dtb, module_base, export_name }. Walks the PE export table.",
	&render_inputs_mex,
	&run_mex);

TESTLAB_REGISTER(g_reg_v2p_memory,
	"memory",
	test_lab::driver_e::whoswho,
	"V2P - virtual to physical translation",
	"ioctl_codes::V2P() with virt_to_phys_request{ dtb, virtual_address }. Walks the page tables.",
	&render_inputs_v2p,
	&run_v2p);
