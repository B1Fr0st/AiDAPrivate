#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4099 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "aida_architecture.hpp"
#include "aida_load_image.hpp"
#include "aida_scope.hpp"
#include "aida_comment_database.hpp"
#include "aida_print_c.hpp"

#include "aida_ghidra_preamble.hpp"

#include "funcdata.hh"
#include "coreaction.hh"
#include "type.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "../../analysis/symbol_store.hpp"
#include "../../analysis/pdb_parser.hpp"
#include "helpers/diag_log.hpp"

namespace aida_ghidra {

namespace {

const std::map<std::string, std::string>& cc_map_x64()
{
	static const std::map<std::string, std::string> map = {
		{ "stdcall", "__stdcall" },
		{ "cdecl", "__cdecl" },
		{ "fastcall", "__fastcall" },
		{ "thiscall", "__thiscall" },
		{ "ms", "__fastcall" },
		{ "win64", "__stdcall" },
		{ "x64", "__stdcall" },
		{ "amd64", "__stdcall" },
		{ "windows", "__stdcall" },
		{ "default", "__stdcall" },
	};
	return map;
}

std::string lowercase_(const std::string& s)
{
	std::string out;
	out.reserve(s.size());
	for (char c : s) {
		out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
	}
	return out;
}

const std::string& require_print_language(const std::string& target)
{
	print_c_capability_t::ensure_registered();
	return target;
}

}

architecture_t::architecture_t(const std::string& target,
                               std::ostream* err_stream)
	: ghidra::SleighArchitecture("aida_program", require_print_language(target), err_stream)
{
}

void architecture_t::take_loader(std::unique_ptr<load_image_t> loader)
{
	staged_loader_ = std::move(loader);
}

ghidra::ProtoModel* architecture_t::proto_model_from_cc(const std::string& cc) const
{
	const auto& m = cc_map_x64();
	auto it = m.find(lowercase_(cc));
	if (it == m.end())
		return nullptr;

	auto proto_it = protoModels.find(it->second);
	if (proto_it == protoModels.end())
		return nullptr;
	return proto_it->second;
}

ghidra::Address architecture_t::register_address_from_name(const std::string& reg_name) const
{
	auto it = registers_.find(reg_name);
	if (it == registers_.end())
		it = registers_.find(lowercase_(reg_name));
	if (it == registers_.end())
		return ghidra::Address();
	return it->second.getAddr();
}

void architecture_t::load_registers_(const ghidra::Translate* trans)
{
	registers_.clear();
	if (!trans)
		return;
	std::map<ghidra::VarnodeData, std::string> regs;
	trans->getAllRegisters(regs);
	for (const auto& reg : regs) {
		registers_[reg.second] = reg.first;
		auto lower = lowercase_(reg.second);
		if (registers_.find(lower) == registers_.end())
			registers_[lower] = reg.first;
	}
}

ghidra::Translate* architecture_t::buildTranslator(ghidra::DocumentStorage& store)
{
	ghidra::Translate* ret = ghidra::SleighArchitecture::buildTranslator(store);
	load_registers_(ret);
	return ret;
}

void architecture_t::buildLoader(ghidra::DocumentStorage& )
{
	collectSpecFiles(*errorstream);
	if (staged_loader_) {
		auto raw = staged_loader_.release();
		raw->set_address_space_manager(this);
		loader = raw;
		owns_loader_ = true;
	}
}

ghidra::Scope* architecture_t::buildDatabase(ghidra::DocumentStorage& )
{
	symboltab = new ghidra::Database(this, false);
	auto* gscope = new scope_t(this);
	symboltab->attachScope(gscope, nullptr);
	return gscope;
}

void architecture_t::buildTypegrp(ghidra::DocumentStorage& )
{
	types = new ghidra::TypeFactory(this);
}

void architecture_t::buildCoreTypes(ghidra::DocumentStorage& )
{
	types->setCoreType("void", 1, ghidra::TYPE_VOID, false);
	types->setCoreType("bool", 1, ghidra::TYPE_BOOL, false);
	types->setCoreType("uint8_t", 1, ghidra::TYPE_UINT, false);
	types->setCoreType("uint16_t", 2, ghidra::TYPE_UINT, false);
	types->setCoreType("uint32_t", 4, ghidra::TYPE_UINT, false);
	types->setCoreType("uint64_t", 8, ghidra::TYPE_UINT, false);
	types->setCoreType("char", 1, ghidra::TYPE_INT, true);
	types->setCoreType("int8_t", 1, ghidra::TYPE_INT, false);
	types->setCoreType("int16_t", 2, ghidra::TYPE_INT, false);
	types->setCoreType("int32_t", 4, ghidra::TYPE_INT, false);
	types->setCoreType("int64_t", 8, ghidra::TYPE_INT, false);
	types->setCoreType("float", 4, ghidra::TYPE_FLOAT, false);
	types->setCoreType("double", 8, ghidra::TYPE_FLOAT, false);
	types->setCoreType("float16", 16, ghidra::TYPE_FLOAT, false);
	types->setCoreType("undefined", 1, ghidra::TYPE_UNKNOWN, false);
	types->setCoreType("undefined2", 2, ghidra::TYPE_UNKNOWN, false);
	types->setCoreType("undefined4", 4, ghidra::TYPE_UNKNOWN, false);
	types->setCoreType("undefined8", 8, ghidra::TYPE_UNKNOWN, false);
	types->setCoreType("code", 1, ghidra::TYPE_CODE, false);
	types->setCoreType("char16_t", 2, ghidra::TYPE_INT, true);
	types->setCoreType("char32_t", 4, ghidra::TYPE_INT, true);
	types->cacheCoreTypes();
}

void architecture_t::buildCommentDB(ghidra::DocumentStorage& )
{
	commentdb = new comment_database_t();
}

void architecture_t::postSpecFile()
{
	for (auto& s : symbol_db_.symbols) {
		if (!s.is_noreturn)
			continue;
		if (s.kind != symbol_kind_t::function && s.kind != symbol_kind_t::import && s.kind != symbol_kind_t::export_)
			continue;
		ghidra::Address addr(getDefaultCodeSpace(), s.address);
		ghidra::Funcdata* fd = symboltab->getGlobalScope()->queryFunction(addr);
		if (!fd)
			continue;
		fd->getFuncProto().setNoReturn(true);
	}
}

void architecture_t::buildAction(ghidra::DocumentStorage& store)
{
	parseExtraRules(store);
	allacts.universalAction(this);
	allacts.resetDefaults();
	if (rawptr_) {
		allacts.cloneGroup("decompile", "decompile-deuglified");
		if (!keep_fixateglobals_)
			allacts.removeFromGroup("decompile-deuglified", "fixateglobals");
		allacts.setCurrent("decompile-deuglified");
	}
}

namespace {

struct parsed_type_ref_t {
	std::string base_name;
	int         pointer_depth = 0;
	int         array_count = 0;
	bool        is_array = false;
};

inline std::string trim_spaces(const std::string& s)
{
	size_t b = 0;
	while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
	size_t e = s.size();
	while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
	return s.substr(b, e - b);
}

inline parsed_type_ref_t parse_pdb_type_name(const std::string& raw)
{
	parsed_type_ref_t out;
	std::string s = trim_spaces(raw);
	if (s.empty()) {
		out.base_name = "undefined";
		return out;
	}

	while (!s.empty() && s.back() == ']') {
		size_t lb = s.rfind('[');
		if (lb == std::string::npos) break;
		std::string num_str = s.substr(lb + 1, s.size() - lb - 2);
		int count = std::atoi(num_str.c_str());
		if (count <= 0) count = 1;
		out.is_array = true;
		if (out.array_count == 0)
			out.array_count = count;
		else
			out.array_count *= count;
		s = trim_spaces(s.substr(0, lb));
	}

	while (!s.empty() && s.back() == '*') {
		out.pointer_depth++;
		s.pop_back();
		s = trim_spaces(s);
	}

	if (s.empty())
		s = "void";
	out.base_name = s;
	return out;
}

inline bool is_pdb_synthetic_name(const std::string& name)
{
	if (name.empty()) return true;
	if (name[0] == '<') return true;
	if (name.find("__unnamed") != std::string::npos) return true;
	if (name.find("<unnamed-tag>") != std::string::npos) return true;
	if (name.find("<anonymous-namespace>") != std::string::npos) return true;
	if (name.find("`anonymous namespace'") != std::string::npos) return true;
	return false;
}

inline ghidra::Datatype* resolve_named_primitive(ghidra::TypeFactory* types, const std::string& name)
{
	if (!types) return nullptr;
	if (name == "void") return types->getTypeVoid();
	if (name == "bool") return types->getBase(1, ghidra::TYPE_BOOL);
	if (name == "char") return types->getBase(1, ghidra::TYPE_INT);
	if (name == "uint8_t" || name == "unsigned char" || name == "BYTE" || name == "UCHAR")
		return types->getBase(1, ghidra::TYPE_UINT);
	if (name == "int8_t" || name == "signed char" || name == "CHAR")
		return types->getBase(1, ghidra::TYPE_INT);
	if (name == "int16_t" || name == "short" || name == "SHORT")
		return types->getBase(2, ghidra::TYPE_INT);
	if (name == "uint16_t" || name == "unsigned short" || name == "USHORT" || name == "WORD" || name == "wchar_t")
		return types->getBase(2, ghidra::TYPE_UINT);
	if (name == "int32_t" || name == "int" || name == "INT" || name == "long" || name == "LONG")
		return types->getBase(4, ghidra::TYPE_INT);
	if (name == "uint32_t" || name == "unsigned int" || name == "UINT" || name == "ULONG" || name == "DWORD" || name == "unsigned long")
		return types->getBase(4, ghidra::TYPE_UINT);
	if (name == "int64_t" || name == "__int64" || name == "long long" || name == "LONG64" || name == "LONGLONG")
		return types->getBase(8, ghidra::TYPE_INT);
	if (name == "uint64_t" || name == "unsigned __int64" || name == "unsigned long long" || name == "ULONG64" || name == "ULONGLONG" || name == "DWORD64" || name == "QWORD" || name == "SIZE_T")
		return types->getBase(8, ghidra::TYPE_UINT);
	if (name == "float")
		return types->getBase(4, ghidra::TYPE_FLOAT);
	if (name == "double")
		return types->getBase(8, ghidra::TYPE_FLOAT);
	if (name == "HRESULT" || name == "NTSTATUS")
		return types->getBase(4, ghidra::TYPE_INT);
	if (name == "BOOL")
		return types->getBase(4, ghidra::TYPE_INT);
	if (name == "BOOLEAN")
		return types->getBase(1, ghidra::TYPE_UINT);
	if (name == "WCHAR" || name == "TCHAR")
		return types->getBase(2, ghidra::TYPE_UINT);
	if (name == "SSIZE_T" || name == "LONG_PTR" || name == "LPARAM" || name == "LRESULT")
		return types->getBase(8, ghidra::TYPE_INT);
	if (name == "ULONG_PTR" || name == "DWORD_PTR" || name == "WPARAM")
		return types->getBase(8, ghidra::TYPE_UINT);
	if (name == "KIRQL")
		return types->getBase(1, ghidra::TYPE_UINT);
	if (name == "ACCESS_MASK")
		return types->getBase(4, ghidra::TYPE_UINT);
	if (name == "HANDLE" || name == "HMODULE" || name == "HINSTANCE" || name == "HWND" ||
		name == "HDC" || name == "HKEY" || name == "HMENU" || name == "HBRUSH" ||
		name == "HBITMAP" || name == "HGDIOBJ" || name == "PVOID" || name == "LPVOID" ||
		name == "LPCVOID") {
		ghidra::Datatype* void_type = types->getTypeVoid();
		if (!void_type) return nullptr;
		int ptr_size = types->getSizeOfPointer();
		if (ptr_size <= 0) ptr_size = 8;
		return types->getTypePointer(ptr_size, void_type, 1);
	}
	if (name == "PHANDLE" || name == "LPHANDLE") {
		ghidra::Datatype* void_type = types->getTypeVoid();
		if (!void_type) return nullptr;
		int ptr_size = types->getSizeOfPointer();
		if (ptr_size <= 0) ptr_size = 8;
		ghidra::Datatype* vp = types->getTypePointer(ptr_size, void_type, 1);
		if (!vp) return nullptr;
		return types->getTypePointer(ptr_size, vp, 1);
	}
	if (name == "LPSTR" || name == "LPCSTR" || name == "PCHAR") {
		ghidra::Datatype* char_type = types->getBase(1, ghidra::TYPE_INT);
		if (!char_type) return nullptr;
		int ptr_size = types->getSizeOfPointer();
		if (ptr_size <= 0) ptr_size = 8;
		return types->getTypePointer(ptr_size, char_type, 1);
	}
	if (name == "LPWSTR" || name == "LPCWSTR" || name == "PWCHAR") {
		ghidra::Datatype* wchar_type = types->getBase(2, ghidra::TYPE_UINT);
		if (!wchar_type) return nullptr;
		int ptr_size = types->getSizeOfPointer();
		if (ptr_size <= 0) ptr_size = 8;
		return types->getTypePointer(ptr_size, wchar_type, 1);
	}
	if (name == "LPBYTE") {
		ghidra::Datatype* byte_type = types->getBase(1, ghidra::TYPE_UINT);
		if (!byte_type) return nullptr;
		int ptr_size = types->getSizeOfPointer();
		if (ptr_size <= 0) ptr_size = 8;
		return types->getTypePointer(ptr_size, byte_type, 1);
	}
	if (name == "LPDWORD" || name == "PULONG") {
		ghidra::Datatype* dword_type = types->getBase(4, ghidra::TYPE_UINT);
		if (!dword_type) return nullptr;
		int ptr_size = types->getSizeOfPointer();
		if (ptr_size <= 0) ptr_size = 8;
		return types->getTypePointer(ptr_size, dword_type, 1);
	}
	return nullptr;
}

inline ghidra::Datatype* resolve_named_lookup(ghidra::TypeFactory* types, const std::string& name)
{
	if (!types) return nullptr;
	if (auto* prim = resolve_named_primitive(types, name))
		return prim;
	return types->findByName(name);
}

inline ghidra::Datatype* apply_pointer_and_array(ghidra::TypeFactory* types,
                                                 ghidra::Datatype* base,
                                                 const parsed_type_ref_t& ref)
{
	if (!types || !base) return base;
	int ptr_size = types->getSizeOfPointer();
	if (ptr_size <= 0) ptr_size = 8;
	for (int i = 0; i < ref.pointer_depth; ++i) {
		base = types->getTypePointer(ptr_size, base, 1);
		if (!base) return nullptr;
	}
	if (ref.is_array && ref.array_count > 0) {
		base = types->getTypeArray(ref.array_count, base);
	}
	return base;
}

inline ghidra::Datatype* resolve_member_type(ghidra::TypeFactory* types,
                                             const pdb_parser::struct_member_t& m)
{
	if (!types) return nullptr;
	parsed_type_ref_t ref = parse_pdb_type_name(m.type_name);

	ghidra::Datatype* base = resolve_named_lookup(types, ref.base_name);
	if (!base) {
		uint64_t fallback_size = m.size;
		if (ref.pointer_depth > 0)
			fallback_size = types->getSizeOfPointer();
		else if (ref.is_array && ref.array_count > 0 && m.size > 0)
			fallback_size = m.size / static_cast<uint64_t>(ref.array_count > 0 ? ref.array_count : 1);
		if (fallback_size == 0)
			fallback_size = 1;
		if (fallback_size > 8) fallback_size = 8;
		base = types->getBase(static_cast<int>(fallback_size), ghidra::TYPE_UNKNOWN);
	}
	if (!base) return nullptr;

	return apply_pointer_and_array(types, base, ref);
}

constexpr size_t kMaxSanitizedNameLen = 256;
constexpr uint64_t kMaxStructSizeBytes = 64ull * 1024ull * 1024ull;
constexpr uint64_t kMaxMembersPerStruct = 4096ull;
constexpr uint64_t kMaxEnumsPerEnumType = 16384ull;

inline bool is_safe_identifier_string(const std::string& s)
{
	if (s.empty()) return false;
	if (s.size() > kMaxSanitizedNameLen) return false;
	for (size_t i = 0; i < s.size(); ++i) {
		unsigned char c = static_cast<unsigned char>(s[i]);
		if (c == 0) return false;
		if (c < 0x20) return false;
		if (c > 0x7E) return false;
	}
	return true;
}

inline std::string sanitized_or_empty(const std::string& s)
{
	if (!is_safe_identifier_string(s)) return std::string();
	return s;
}

struct member_snap_t {
	std::string name;
	std::string type_name;
	uint64_t    offset = 0;
	uint64_t    size = 0;
	int         bit_size = -1;
};

inline ghidra::Datatype* resolve_member_type_from_snap(ghidra::TypeFactory* types,
                                                       const member_snap_t& m)
{
	if (!types) return nullptr;
	parsed_type_ref_t ref = parse_pdb_type_name(m.type_name);

	ghidra::Datatype* base = resolve_named_lookup(types, ref.base_name);
	if (!base) {
		uint64_t fallback_size = m.size;
		if (ref.pointer_depth > 0)
			fallback_size = types->getSizeOfPointer();
		else if (ref.is_array && ref.array_count > 0 && m.size > 0)
			fallback_size = m.size / static_cast<uint64_t>(ref.array_count > 0 ? ref.array_count : 1);
		if (fallback_size == 0)
			fallback_size = 1;
		if (fallback_size > 8) fallback_size = 8;
		base = types->getBase(static_cast<int>(fallback_size), ghidra::TYPE_UNKNOWN);
	}
	if (!base) return nullptr;

	return apply_pointer_and_array(types, base, ref);
}

struct struct_snap_t {
	std::string                 name;
	uint64_t                    size = 0;
	bool                        is_union = false;
	std::vector<member_snap_t>  members;
};

struct enum_snap_t {
	std::string                 name;
	std::vector<std::pair<int64_t, std::string>> members;
};

struct pdb_snapshot_t {
	std::vector<struct_snap_t>  structs;
	std::vector<enum_snap_t>    enums;
};

inline void take_pdb_snapshot(pdb_snapshot_t& out, size_t& modules_scanned, size_t& skipped_invalid)
{
	out.structs.clear();
	out.enums.clear();
	modules_scanned = 0;
	skipped_invalid = 0;

	std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
	for (auto& kv : symbol_store::g_state.modules) {
		const auto& ms = kv.second;
		if (!ms.pdb.loaded) continue;
		++modules_scanned;

		out.structs.reserve(out.structs.size() + ms.pdb.structs.size());
		for (const auto& s : ms.pdb.structs) {
			if (!is_safe_identifier_string(s.name)) { ++skipped_invalid; continue; }
			if (is_pdb_synthetic_name(s.name)) { ++skipped_invalid; continue; }
			if (s.size == 0 || s.size > kMaxStructSizeBytes) { ++skipped_invalid; continue; }
			if (s.members.empty()) { ++skipped_invalid; continue; }
			if (s.members.size() > kMaxMembersPerStruct) { ++skipped_invalid; continue; }

			struct_snap_t snap;
			snap.name = s.name;
			snap.size = s.size;
			snap.is_union = s.is_union;
			snap.members.reserve(s.members.size());
			bool member_ok = true;
			for (const auto& m : s.members) {
				if (!is_safe_identifier_string(m.name)) { member_ok = false; break; }
				member_snap_t ms_snap;
				ms_snap.name = m.name;
				ms_snap.type_name = is_safe_identifier_string(m.type_name) ? m.type_name : std::string("undefined");
				ms_snap.offset = m.offset;
				ms_snap.size = m.size;
				ms_snap.bit_size = m.bit_size;
				snap.members.push_back(std::move(ms_snap));
			}
			if (!member_ok) { ++skipped_invalid; continue; }
			out.structs.push_back(std::move(snap));
		}

		out.enums.reserve(out.enums.size() + ms.pdb.enums.size());
		for (const auto& e : ms.pdb.enums) {
			if (!is_safe_identifier_string(e.name)) { ++skipped_invalid; continue; }
			if (is_pdb_synthetic_name(e.name)) { ++skipped_invalid; continue; }
			if (e.members.size() > kMaxEnumsPerEnumType) { ++skipped_invalid; continue; }

			enum_snap_t snap;
			snap.name = e.name;
			snap.members.reserve(e.members.size());
			for (const auto& em : e.members) {
				if (!is_safe_identifier_string(em.name)) continue;
				snap.members.emplace_back(em.value, em.name);
			}
			out.enums.push_back(std::move(snap));
		}
	}
}

thread_local std::string tl_current_apply_name;
thread_local const char* tl_current_apply_stage = "idle";
inline std::mutex& apply_pdb_global_mutex()
{
	static std::mutex m;
	return m;
}

__declspec(noinline) static ghidra::TypeStruct* call_get_type_struct(ghidra::TypeFactory* types, const std::string& n)
{
	return types->getTypeStruct(n);
}

__declspec(noinline) static ghidra::TypeUnion* call_get_type_union(ghidra::TypeFactory* types, const std::string& n)
{
	return types->getTypeUnion(n);
}

__declspec(noinline) static ghidra::TypeEnum* call_get_type_enum(ghidra::TypeFactory* types, const std::string& n)
{
	return types->getTypeEnum(n);
}

__declspec(noinline) static ghidra::Datatype* call_find_by_name(ghidra::TypeFactory* types, const std::string& n)
{
	return types->findByName(n);
}

struct name_args_t {
	ghidra::TypeFactory* types;
	const std::string*   name;
	void*                out;
};

__declspec(noinline) static DWORD seh_run_get_type_struct(name_args_t* a)
{
	__try {
		*reinterpret_cast<ghidra::TypeStruct**>(a->out) = call_get_type_struct(a->types, *a->name);
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		*reinterpret_cast<ghidra::TypeStruct**>(a->out) = nullptr;
		return GetExceptionCode();
	}
}

__declspec(noinline) static DWORD seh_run_get_type_union(name_args_t* a)
{
	__try {
		*reinterpret_cast<ghidra::TypeUnion**>(a->out) = call_get_type_union(a->types, *a->name);
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		*reinterpret_cast<ghidra::TypeUnion**>(a->out) = nullptr;
		return GetExceptionCode();
	}
}

__declspec(noinline) static DWORD seh_run_get_type_enum(name_args_t* a)
{
	__try {
		*reinterpret_cast<ghidra::TypeEnum**>(a->out) = call_get_type_enum(a->types, *a->name);
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		*reinterpret_cast<ghidra::TypeEnum**>(a->out) = nullptr;
		return GetExceptionCode();
	}
}

__declspec(noinline) static DWORD seh_run_find_by_name(name_args_t* a)
{
	__try {
		*reinterpret_cast<ghidra::Datatype**>(a->out) = call_find_by_name(a->types, *a->name);
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		*reinterpret_cast<ghidra::Datatype**>(a->out) = nullptr;
		return GetExceptionCode();
	}
}

inline ghidra::TypeStruct* seh_get_type_struct(ghidra::TypeFactory* types, const std::string& n)
{
	ghidra::TypeStruct* out = nullptr;
	name_args_t a{ types, &n, &out };
	seh_run_get_type_struct(&a);
	return out;
}

inline ghidra::TypeUnion* seh_get_type_union(ghidra::TypeFactory* types, const std::string& n)
{
	ghidra::TypeUnion* out = nullptr;
	name_args_t a{ types, &n, &out };
	seh_run_get_type_union(&a);
	return out;
}

inline ghidra::TypeEnum* seh_get_type_enum(ghidra::TypeFactory* types, const std::string& n)
{
	ghidra::TypeEnum* out = nullptr;
	name_args_t a{ types, &n, &out };
	seh_run_get_type_enum(&a);
	return out;
}

inline ghidra::Datatype* seh_find_by_name(ghidra::TypeFactory* types, const std::string& n)
{
	ghidra::Datatype* out = nullptr;
	name_args_t a{ types, &n, &out };
	seh_run_find_by_name(&a);
	return out;
}

struct assign_struct_args_t {
	ghidra::TypeFactory*              types;
	ghidra::TypeStruct*               ts;
	std::vector<ghidra::TypeField>*   fields;
	std::vector<ghidra::TypeBitField>* bits;
};

__declspec(noinline) static bool call_assign_struct(assign_struct_args_t* a)
{
	try {
		a->types->assignRawFields(a->ts, *a->fields, *a->bits);
		return true;
	} catch (...) {
		return false;
	}
}

__declspec(noinline) static DWORD seh_assign_struct(assign_struct_args_t* a)
{
	__try {
		return call_assign_struct(a) ? 0u : 0xC0000FFEu;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}

struct assign_union_args_t {
	ghidra::TypeFactory*            types;
	ghidra::TypeUnion*              tu;
	std::vector<ghidra::TypeField>* fields;
};

__declspec(noinline) static bool call_assign_union(assign_union_args_t* a)
{
	try {
		a->types->assignRawFields(a->tu, *a->fields);
		return true;
	} catch (...) {
		return false;
	}
}

__declspec(noinline) static DWORD seh_assign_union(assign_union_args_t* a)
{
	__try {
		return call_assign_union(a) ? 0u : 0xC0000FFEu;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}

struct set_enum_args_t {
	ghidra::TypeFactory*                            types;
	ghidra::TypeEnum*                               te;
	const std::map<ghidra::uintb, std::string>*    nmap;
};

__declspec(noinline) static bool call_set_enum_values(set_enum_args_t* a)
{
	try {
		a->types->setEnumValues(*a->nmap, a->te);
		return true;
	} catch (...) {
		return false;
	}
}

__declspec(noinline) static DWORD seh_set_enum_values(set_enum_args_t* a)
{
	__try {
		return call_set_enum_values(a) ? 0u : 0xC0000FFEu;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}

__declspec(noinline) static bool call_is_incomplete(ghidra::Datatype* dt)
{
	return dt && dt->isIncomplete();
}

__declspec(noinline) static bool seh_is_incomplete(ghidra::Datatype* dt)
{
	__try {
		return call_is_incomplete(dt);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

__declspec(noinline) static int call_dt_size(ghidra::Datatype* dt)
{
	return dt ? dt->getSize() : 0;
}

__declspec(noinline) static int seh_dt_size(ghidra::Datatype* dt)
{
	__try {
		return call_dt_size(dt);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
}

inline ghidra::Datatype* make_padding_type(ghidra::TypeFactory* types, ghidra::int4 nbytes)
{
	if (!types || nbytes <= 0) return nullptr;
	ghidra::Datatype* unit = types->getBase(1, ghidra::TYPE_UNKNOWN);
	if (!unit) return nullptr;
	if (nbytes == 1) return unit;
	return types->getTypeArray(nbytes, unit);
}

__declspec(noinline) static ghidra::TypeStruct* call_dyncast_struct(ghidra::Datatype* dt)
{
	return dynamic_cast<ghidra::TypeStruct*>(dt);
}

__declspec(noinline) static ghidra::TypeUnion* call_dyncast_union(ghidra::Datatype* dt)
{
	return dynamic_cast<ghidra::TypeUnion*>(dt);
}

__declspec(noinline) static ghidra::TypeEnum* call_dyncast_enum(ghidra::Datatype* dt)
{
	return dynamic_cast<ghidra::TypeEnum*>(dt);
}

struct dyncast_args_t {
	ghidra::Datatype* in;
	void*             out;
};

__declspec(noinline) static DWORD seh_run_dyncast_struct(dyncast_args_t* a)
{
	__try {
		*reinterpret_cast<ghidra::TypeStruct**>(a->out) = call_dyncast_struct(a->in);
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		*reinterpret_cast<ghidra::TypeStruct**>(a->out) = nullptr;
		return GetExceptionCode();
	}
}

__declspec(noinline) static DWORD seh_run_dyncast_union(dyncast_args_t* a)
{
	__try {
		*reinterpret_cast<ghidra::TypeUnion**>(a->out) = call_dyncast_union(a->in);
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		*reinterpret_cast<ghidra::TypeUnion**>(a->out) = nullptr;
		return GetExceptionCode();
	}
}

__declspec(noinline) static DWORD seh_run_dyncast_enum(dyncast_args_t* a)
{
	__try {
		*reinterpret_cast<ghidra::TypeEnum**>(a->out) = call_dyncast_enum(a->in);
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		*reinterpret_cast<ghidra::TypeEnum**>(a->out) = nullptr;
		return GetExceptionCode();
	}
}

inline ghidra::TypeStruct* seh_dyncast_struct(ghidra::Datatype* dt)
{
	ghidra::TypeStruct* out = nullptr;
	dyncast_args_t a{ dt, &out };
	seh_run_dyncast_struct(&a);
	return out;
}

inline ghidra::TypeUnion* seh_dyncast_union(ghidra::Datatype* dt)
{
	ghidra::TypeUnion* out = nullptr;
	dyncast_args_t a{ dt, &out };
	seh_run_dyncast_union(&a);
	return out;
}

inline ghidra::TypeEnum* seh_dyncast_enum(ghidra::Datatype* dt)
{
	ghidra::TypeEnum* out = nullptr;
	dyncast_args_t a{ dt, &out };
	seh_run_dyncast_enum(&a);
	return out;
}

}

std::string architecture_t::current_apply_pdb_name()
{
	return tl_current_apply_name;
}

const char* architecture_t::current_apply_pdb_stage()
{
	return tl_current_apply_stage ? tl_current_apply_stage : "idle";
}

void architecture_t::apply_pdb_types()
{
	if (!types) {
		diag::log_tagged_critical("dec_pdb", "apply_pdb_types_exit reason=no_typefactory");
		return;
	}

	std::lock_guard<std::mutex> glk(apply_pdb_global_mutex());

	auto t_start = std::chrono::steady_clock::now();

	pdb_snapshot_t snap;
	size_t modules_scanned = 0;
	size_t skipped_invalid = 0;
	take_pdb_snapshot(snap, modules_scanned, skipped_invalid);

	diag::log_tagged_critical_fmt("dec_pdb",
		"apply_pdb_types_enter modules=%zu structs=%zu enums=%zu pre_skipped=%zu",
		modules_scanned, snap.structs.size(), snap.enums.size(), skipped_invalid);

	if (snap.structs.empty() && snap.enums.empty()) {
		diag::log_tagged_critical("dec_pdb", "apply_pdb_types_exit reason=empty_snapshot");
		return;
	}

	std::unordered_set<std::string> declared_struct_names;
	std::unordered_set<std::string> declared_enum_names;
	size_t declared_struct_count = 0;
	size_t declared_union_count = 0;
	size_t declared_enum_count = 0;
	size_t skipped_declare = 0;

	tl_current_apply_stage = "declare";
	for (size_t i = 0; i < snap.structs.size(); ++i) {
		auto& s = snap.structs[i];
		if (declared_struct_names.count(s.name)) { ++skipped_declare; continue; }
		if (resolve_named_primitive(types, s.name)) { ++skipped_declare; continue; }

		tl_current_apply_name = s.name;
		if (s.is_union) {
			ghidra::TypeUnion* tu = seh_get_type_union(types, s.name);
			if (tu) ++declared_union_count;
			else {
				diag::log_tagged_critical_fmt("dec_pdb",
					"apply_pdb_types_seh_fault stage=declare_union name=%s",
					s.name.c_str());
				continue;
			}
		} else {
			ghidra::TypeStruct* ts = seh_get_type_struct(types, s.name);
			if (ts) ++declared_struct_count;
			else {
				diag::log_tagged_critical_fmt("dec_pdb",
					"apply_pdb_types_seh_fault stage=declare_struct name=%s",
					s.name.c_str());
				continue;
			}
		}
		declared_struct_names.insert(s.name);
	}

	for (size_t i = 0; i < snap.enums.size(); ++i) {
		auto& e = snap.enums[i];
		if (declared_enum_names.count(e.name)) { ++skipped_declare; continue; }
		tl_current_apply_name = e.name;
		ghidra::TypeEnum* te = seh_get_type_enum(types, e.name);
		if (te) ++declared_enum_count;
		else {
			diag::log_tagged_critical_fmt("dec_pdb",
				"apply_pdb_types_seh_fault stage=declare_enum name=%s",
				e.name.c_str());
			continue;
		}
		declared_enum_names.insert(e.name);
	}

	size_t structs_complete = 0;
	size_t unions_complete = 0;
	size_t enums_complete = 0;
	size_t skipped_complete = 0;
	size_t fail_assign = 0;

	tl_current_apply_stage = "complete_struct";
	for (size_t i = 0; i < snap.structs.size(); ++i) {
		auto& s = snap.structs[i];
		tl_current_apply_name = s.name;

		if (resolve_named_primitive(types, s.name)) { ++skipped_complete; continue; }

		ghidra::Datatype* existing = seh_find_by_name(types, s.name);
		if (!existing) {
			diag::log_tagged_critical_fmt("dec_pdb",
				"apply_pdb_types_struct_skip name=%s reason=not_found",
				s.name.c_str());
			++skipped_complete;
			continue;
		}
		if (!seh_is_incomplete(existing)) {
			++skipped_complete;
			continue;
		}

		if (s.is_union) {
			ghidra::TypeUnion* tu = seh_dyncast_union(existing);
			if (!tu) { ++skipped_complete; continue; }

			std::vector<ghidra::TypeField> fields;
			fields.reserve(s.members.size());
			ghidra::int4 ident = 0;
			for (auto& m : s.members) {
				if (m.bit_size >= 0) continue;
				ghidra::Datatype* mtype = resolve_member_type_from_snap(types, m);
				if (!mtype) continue;
				int dt_sz = seh_dt_size(mtype);
				if (dt_sz <= 0) continue;
				fields.emplace_back(ident++, -1, m.name, mtype);
			}
			if (fields.empty()) { ++skipped_complete; continue; }

			assign_union_args_t a{ types, tu, &fields };
			DWORD code = seh_assign_union(&a);
			if (code != 0) {
				diag::log_tagged_critical_fmt("dec_pdb",
					"apply_pdb_types_struct_post name=%s outcome=failed_assign_union code=0x%08X fields=%zu",
					s.name.c_str(), code, fields.size());
				++fail_assign;
				continue;
			}
			++unions_complete;
		} else {
			ghidra::TypeStruct* ts = seh_dyncast_struct(existing);
			if (!ts) { ++skipped_complete; continue; }

			std::vector<member_snap_t> sorted = s.members;
			std::sort(sorted.begin(), sorted.end(),
				[](const member_snap_t& a, const member_snap_t& b) { return a.offset < b.offset; });

			std::vector<ghidra::TypeField> fields;
			std::vector<ghidra::TypeBitField> bitfields;
			fields.reserve(sorted.size() + 4);
			ghidra::int4 ident = 0;
			uint64_t cursor = 0;
			uint64_t last_consumed_end = 0;
			bool any_added = false;
			bool field_overflow = false;

			for (auto& m : sorted) {
				if (m.bit_size >= 0) continue;
				ghidra::Datatype* mtype = resolve_member_type_from_snap(types, m);
				if (!mtype) continue;
				int dt_sz = seh_dt_size(mtype);
				if (dt_sz <= 0) continue;
				uint64_t field_size = static_cast<uint64_t>(dt_sz);
				uint64_t end = m.offset + field_size;
				if (end > s.size) { field_overflow = true; continue; }
				if (m.offset < last_consumed_end) continue;

				if (m.offset > cursor) {
					uint64_t gap = m.offset - cursor;
					if (gap > 0 && gap <= s.size) {
						ghidra::Datatype* pad = make_padding_type(types, static_cast<ghidra::int4>(gap));
						if (pad) {
							char pname[32];
							_snprintf_s(pname, sizeof(pname), _TRUNCATE, "_pad_0x%llx",
								static_cast<unsigned long long>(cursor));
							fields.emplace_back(ident++, -1, std::string(pname), pad);
						}
					}
				}

				fields.emplace_back(ident++, -1, m.name, mtype);
				cursor = end;
				last_consumed_end = end;
				any_added = true;
			}

			if (!any_added) {
				if (field_overflow) {
					diag::log_tagged_critical_fmt("dec_pdb",
						"apply_pdb_types_struct_post name=%s outcome=skipped_all_overflow size=%llu members=%zu",
						s.name.c_str(),
						static_cast<unsigned long long>(s.size),
						sorted.size());
				}
				++skipped_complete;
				continue;
			}

			if (s.size > cursor) {
				uint64_t gap = s.size - cursor;
				if (gap > 0 && gap <= s.size) {
					ghidra::Datatype* pad = make_padding_type(types, static_cast<ghidra::int4>(gap));
					if (pad) {
						char pname[32];
						_snprintf_s(pname, sizeof(pname), _TRUNCATE, "_pad_0x%llx",
							static_cast<unsigned long long>(cursor));
						fields.emplace_back(ident++, -1, std::string(pname), pad);
					}
				}
			}

			assign_struct_args_t a{ types, ts, &fields, &bitfields };
			DWORD code = seh_assign_struct(&a);
			if (code != 0) {
				diag::log_tagged_critical_fmt("dec_pdb",
					"apply_pdb_types_struct_post name=%s outcome=failed_assign_struct code=0x%08X fields=%zu size=%llu",
					s.name.c_str(), code, fields.size(),
					static_cast<unsigned long long>(s.size));
				++fail_assign;
				continue;
			}
			++structs_complete;
		}
	}

	tl_current_apply_stage = "complete_enum";
	for (size_t i = 0; i < snap.enums.size(); ++i) {
		auto& e = snap.enums[i];
		tl_current_apply_name = e.name;

		ghidra::Datatype* existing = seh_find_by_name(types, e.name);
		if (!existing) { ++skipped_complete; continue; }
		ghidra::TypeEnum* te = seh_dyncast_enum(existing);
		if (!te) { ++skipped_complete; continue; }

		std::map<ghidra::uintb, std::string> nmap;
		for (auto& em : e.members) {
			ghidra::uintb key = static_cast<ghidra::uintb>(em.first);
			if (nmap.find(key) != nmap.end()) continue;
			nmap[key] = em.second;
		}
		if (nmap.empty()) { ++skipped_complete; continue; }

		set_enum_args_t a{ types, te, &nmap };
		DWORD code = seh_set_enum_values(&a);
		if (code != 0) {
			diag::log_tagged_critical_fmt("dec_pdb",
				"apply_pdb_types_enum_post name=%s outcome=failed_set_enum code=0x%08X members=%zu",
				e.name.c_str(), code, nmap.size());
			++fail_assign;
			continue;
		}
		++enums_complete;
	}

	tl_current_apply_stage = "idle";
	tl_current_apply_name.clear();

	auto t_end = std::chrono::steady_clock::now();
	auto dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();

	diag::log_tagged_critical_fmt("dec_pdb",
		"apply_pdb_types_exit structs_decl=%zu structs_complete=%zu unions_complete=%zu enums_decl=%zu enums_complete=%zu skipped_decl=%zu skipped_complete=%zu fail_assign=%zu duration_ms=%lld",
		declared_struct_count,
		structs_complete,
		unions_complete,
		declared_enum_count,
		enums_complete,
		skipped_declare,
		skipped_complete,
		fail_assign,
		static_cast<long long>(dur_ms));
}

namespace {

struct parsed_proto_param_t {
	parsed_type_ref_t type;
	std::string       name;
};

struct parsed_signature_t {
	bool                        valid = false;
	bool                        has_return_type = false;
	parsed_type_ref_t           return_type;
	std::vector<parsed_proto_param_t> params;
	bool                        varargs = false;
	std::string                 calling_convention;
};

inline bool proto_ident_char(char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '_';
}

inline bool read_msvc_scoped_name(const std::string& s, size_t& i, std::vector<std::string>& scopes)
{
	while (true) {
		std::string ident;
		while (i < s.size() && proto_ident_char(s[i]))
			ident.push_back(s[i++]);
		if (ident.empty())
			return false;
		scopes.push_back(std::move(ident));
		if (i < s.size() && s[i] == '@') {
			++i;
			if (i < s.size() && s[i] == '@') {
				++i;
				return true;
			}
			continue;
		}
		return false;
	}
}

inline bool read_msvc_type(const std::string& s, size_t& i, parsed_type_ref_t& out)
{
	if (i >= s.size())
		return false;
	const char c = s[i];
	switch (c) {
	case 'X': ++i; out.base_name = "void"; return true;
	case 'D': ++i; out.base_name = "char"; return true;
	case 'E': ++i; out.base_name = "unsigned char"; return true;
	case 'F': ++i; out.base_name = "short"; return true;
	case 'G': ++i; out.base_name = "unsigned short"; return true;
	case 'H': ++i; out.base_name = "int"; return true;
	case 'I': ++i; out.base_name = "unsigned int"; return true;
	case 'J': ++i; out.base_name = "long"; return true;
	case 'K': ++i; out.base_name = "unsigned long"; return true;
	case 'M': ++i; out.base_name = "float"; return true;
	case 'N': ++i; out.base_name = "double"; return true;
	case 'O': ++i; out.base_name = "double"; return true;
	default: break;
	}
	if (c == '_') {
		if (i + 1 >= s.size())
			return false;
		const char n = s[i + 1];
		i += 2;
		switch (n) {
		case 'N': out.base_name = "bool"; return true;
		case 'J': out.base_name = "__int64"; return true;
		case 'K': out.base_name = "unsigned __int64"; return true;
		case 'L': out.base_name = "long long"; return true;
		case 'W': out.base_name = "wchar_t"; return true;
		default: return false;
		}
	}
	if (c == 'U' || c == 'V' || c == 'W') {
		++i;
		if (c == 'W') {
			if (i >= s.size() || s[i] < '0' || s[i] > '9')
				return false;
			++i;
		}
		std::vector<std::string> scopes;
		if (!read_msvc_scoped_name(s, i, scopes))
			return false;
		std::string name = scopes.front();
		for (size_t k = 1; k < scopes.size(); ++k) {
			name += "::";
			name += scopes[k];
		}
		out.base_name = name;
		return true;
	}
	if (c == 'P' || c == 'A') {
		++i;
		if (c == 'P' && i < s.size() && s[i] == 'E')
			++i;
		if (i >= s.size())
			return false;
		const char cv = s[i];
		if (cv != 'A' && cv != 'B' && cv != 'C' && cv != 'D')
			return false;
		++i;
		if (i < s.size() && s[i] == '6')
			return false;
		parsed_type_ref_t inner;
		if (!read_msvc_type(s, i, inner))
			return false;
		if (inner.is_array)
			return false;
		out = inner;
		out.pointer_depth = inner.pointer_depth + 1;
		return true;
	}
	return false;
}

inline parsed_signature_t parse_msvc_signature(const std::string& s)
{
	parsed_signature_t sig;
	if (s.size() < 6 || s[0] != '?')
		return sig;
	if (s[1] == '?' || s[1] == '$')
		return sig;
	size_t i = 1;
	std::vector<std::string> scopes;
	if (!read_msvc_scoped_name(s, i, scopes))
		return sig;
	if (i >= s.size())
		return sig;
	const char frame = s[i];
	if (frame == 'Y') {
		++i;
	} else if (frame == 'Q' || frame == 'R' || frame == 'S') {
		++i;
		if (i >= s.size() || (s[i] != 'A' && s[i] != 'B'))
			return sig;
		++i;
	} else {
		return sig;
	}
	if (i >= s.size())
		return sig;
	const char conv = s[i++];
	switch (conv) {
	case 'A':
	case 'B': sig.calling_convention = "cdecl"; break;
	case 'C': sig.calling_convention = "fastcall"; break;
	case 'E': sig.calling_convention = "thiscall"; break;
	case 'G': sig.calling_convention = "stdcall"; break;
	default: return sig;
	}
	if (!read_msvc_type(s, i, sig.return_type))
		return sig;
	sig.has_return_type = true;
	if (i >= s.size())
		return sig;
	if (s[i] == 'X') {
		parsed_type_ref_t void_marker;
		if (!read_msvc_type(s, i, void_marker))
			return sig;
	} else {
		while (i < s.size() && s[i] != 'Z') {
			parsed_proto_param_t param;
			if (!read_msvc_type(s, i, param.type))
				return sig;
			sig.params.push_back(std::move(param));
		}
	}
	if (i >= s.size() || s[i] != 'Z')
		return sig;
	++i;
	if (i < s.size() && s[i] == 'Z') {
		sig.varargs = true;
		++i;
	}
	if (i != s.size())
		return sig;
	sig.valid = true;
	return sig;
}

inline bool is_type_keyword_word(const std::string& s)
{
	static const std::unordered_set<std::string> words = {
		"void", "char", "short", "int", "long", "float", "double",
		"bool", "signed", "unsigned", "wchar_t", "__int64"
	};
	return words.find(s) != words.end();
}

inline bool is_type_modifier_word(const std::string& s)
{
	static const std::unordered_set<std::string> words = {
		"const", "volatile", "unsigned", "signed", "long", "short",
		"struct", "enum", "union", "class"
	};
	return words.find(s) != words.end();
}

inline std::string last_word_of(const std::string& s)
{
	size_t e = s.size();
	while (e > 0 && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
	size_t b = e;
	while (b > 0 && !std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
	return s.substr(b, e - b);
}

inline void strip_leading_qualifiers(std::string& s)
{
	while (true) {
		std::string t = trim_spaces(s);
		const char* prefixes[] = { "const ", "volatile ", "struct ", "enum ", "union ", "class " };
		bool stripped = false;
		for (const char* p : prefixes) {
			const size_t n = std::strlen(p);
			if (t.size() > n && t.compare(0, n, p) == 0) {
				s = trim_spaces(t.substr(n));
				stripped = true;
				break;
			}
		}
		if (!stripped) {
			s = t;
			return;
		}
	}
}

inline void normalize_parsed_ref(parsed_type_ref_t& ref)
{
	while (ref.base_name.size() > 6 &&
		ref.base_name.compare(ref.base_name.size() - 6, 6, " const") == 0) {
		ref.base_name = trim_spaces(ref.base_name.substr(0, ref.base_name.size() - 6));
	}
}

inline std::vector<std::string> split_top_level_commas(const std::string& s)
{
	std::vector<std::string> parts;
	int depth = 0;
	size_t begin = 0;
	for (size_t i = 0; i < s.size(); ++i) {
		const char c = s[i];
		if (c == '(' || c == '[' || c == '{')
			++depth;
		else if (c == ')' || c == ']' || c == '}')
			--depth;
		else if (c == ',' && depth == 0) {
			parts.push_back(s.substr(begin, i - begin));
			begin = i + 1;
		}
	}
	parts.push_back(s.substr(begin));
	return parts;
}

inline bool parse_cdecl_param(const std::string& raw, parsed_proto_param_t& out, bool& varargs)
{
	std::string p = trim_spaces(raw);
	if (p == "...") {
		varargs = true;
		return true;
	}
	if (p.empty())
		return false;
	strip_leading_qualifiers(p);
	if (p.empty())
		return false;
	size_t b = p.size();
	while (b > 0 && proto_ident_char(p[b - 1]))
		--b;
	const std::string trailing = p.substr(b);
	const std::string prefix = trim_spaces(p.substr(0, b));
	if (!trailing.empty() && !prefix.empty() && !is_type_keyword_word(trailing) &&
		(prefix.back() == '*' || prefix.back() == ']' ||
		 !is_type_modifier_word(last_word_of(prefix)))) {
		out.name = trailing;
		p = prefix;
	}
	out.type = parse_pdb_type_name(p);
	normalize_parsed_ref(out.type);
	return !out.type.base_name.empty();
}

inline parsed_signature_t parse_cdecl_signature(const std::string& s)
{
	parsed_signature_t sig;
	const size_t lp = s.find('(');
	if (lp == std::string::npos)
		return sig;
	const size_t rp = s.rfind(')');
	if (rp == std::string::npos || rp < lp)
		return sig;
	const std::string tail = trim_spaces(s.substr(rp + 1));
	if (!tail.empty() && tail != "const" && tail != "noexcept")
		return sig;
	if (s.find('<') != std::string::npos)
		return sig;
	const std::string head = trim_spaces(s.substr(0, lp));
	if (head.empty())
		return sig;
	std::vector<std::string> tokens;
	{
		std::string cur;
		for (const char c : head) {
			if (std::isspace(static_cast<unsigned char>(c))) {
				if (!cur.empty()) {
					tokens.push_back(cur);
					cur.clear();
				}
			} else {
				cur.push_back(c);
			}
		}
		if (!cur.empty())
			tokens.push_back(cur);
	}
	if (tokens.empty())
		return sig;
	const std::string& name = tokens.back();
	for (const char c : name) {
		if (!proto_ident_char(c) && c != ':' && c != '~')
			return sig;
	}
	std::vector<std::string> return_tokens;
	for (size_t k = 0; k + 1 < tokens.size(); ++k) {
		const std::string& t = tokens[k];
		if (t == "__cdecl") { sig.calling_convention = "cdecl"; continue; }
		if (t == "__stdcall") { sig.calling_convention = "stdcall"; continue; }
		if (t == "__fastcall") { sig.calling_convention = "fastcall"; continue; }
		if (t == "__thiscall") { sig.calling_convention = "thiscall"; continue; }
		if (t == "__vectorcall" || t == "__clrcall")
			return sig;
		return_tokens.push_back(t);
	}
	if (!return_tokens.empty()) {
		std::string joined = return_tokens.front();
		for (size_t k = 1; k < return_tokens.size(); ++k) {
			joined.push_back(' ');
			joined += return_tokens[k];
		}
		strip_leading_qualifiers(joined);
		sig.return_type = parse_pdb_type_name(joined);
		normalize_parsed_ref(sig.return_type);
		sig.has_return_type = !sig.return_type.base_name.empty();
	}
	const std::string params_str = s.substr(lp + 1, rp - lp - 1);
	const std::string trimmed_params = trim_spaces(params_str);
	if (!trimmed_params.empty() && trimmed_params != "void") {
		const auto parts = split_top_level_commas(params_str);
		for (size_t k = 0; k < parts.size(); ++k) {
			parsed_proto_param_t param;
			bool varargs_here = false;
			if (!parse_cdecl_param(parts[k], param, varargs_here))
				return sig;
			if (varargs_here) {
				if (k + 1 != parts.size())
					return sig;
				sig.varargs = true;
				continue;
			}
			sig.params.push_back(std::move(param));
		}
	}
	sig.valid = true;
	return sig;
}

inline parsed_signature_t parse_symbol_signature(const std::string& display_name)
{
	if (display_name.empty())
		return {};
	if (display_name[0] == '?')
		return parse_msvc_signature(display_name);
	if (display_name.find('(') != std::string::npos)
		return parse_cdecl_signature(display_name);
	return {};
}

inline ghidra::Datatype* resolve_proto_param_type(ghidra::TypeFactory* types,
                                                  const parsed_type_ref_t& ref)
{
	if (!types)
		return nullptr;
	ghidra::Datatype* base = resolve_named_primitive(types, ref.base_name);
	if (!base)
		base = resolve_named_lookup(types, ref.base_name);
	if (!base)
		return nullptr;
	return apply_pointer_and_array(types, base, ref);
}

struct symbol_proto_job_t {
	architecture_t*               arch = nullptr;
	ghidra::Funcdata*             fd = nullptr;
	const parsed_signature_t*     sig = nullptr;
	ghidra::ProtoModel*           cc_model = nullptr;
	bool                          unresolved = false;
	bool                          applied = false;
};

__declspec(noinline) static bool call_apply_symbol_proto(symbol_proto_job_t* job)
{
	try {
		if (!job || !job->arch || !job->fd || !job->sig)
			return false;
		ghidra::TypeFactory* types = job->arch->types;
		if (!types)
			return false;
		ghidra::FuncProto& fp = job->fd->getFuncProto();
		ghidra::Datatype* return_type = nullptr;
		if (job->sig->has_return_type) {
			return_type = resolve_proto_param_type(types, job->sig->return_type);
			if (!return_type) {
				job->unresolved = true;
				return false;
			}
		}
		std::vector<ghidra::Datatype*> param_types;
		std::vector<std::string> param_names;
		param_types.reserve(job->sig->params.size());
		param_names.reserve(job->sig->params.size());
		for (const auto& param : job->sig->params) {
			ghidra::Datatype* t = resolve_proto_param_type(types, param.type);
			if (!t) {
				job->unresolved = true;
				return false;
			}
			param_types.push_back(t);
			param_names.push_back(param.name);
		}
		if (job->cc_model)
			fp.setModel(job->cc_model);
		if (!fp.hasModel())
			return false;
		const auto model_it = job->arch->protoModels.find(fp.getModelName());
		if (model_it == job->arch->protoModels.end() || !model_it->second)
			return false;
		ghidra::PrototypePieces pieces;
		pieces.model = model_it->second;
		pieces.outtype = return_type ? return_type : fp.getOutputType();
		if (!pieces.outtype)
			return false;
		pieces.intypes = std::move(param_types);
		pieces.innames = std::move(param_names);
		while (pieces.innames.size() < pieces.intypes.size())
			pieces.innames.emplace_back();
		pieces.firstVarArgSlot = job->sig->varargs
			? static_cast<ghidra::int4>(pieces.intypes.size()) : -1;
		fp.updateAllTypes(pieces);
		if (fp.hasInputErrors())
			return false;
		fp.setInputLock(true);
		fp.setOutputLock(true);
		fp.setModelLock(true);
		job->applied = true;
		return true;
	} catch (...) {
		return false;
	}
}

__declspec(noinline) static DWORD seh_apply_symbol_proto(symbol_proto_job_t* job)
{
	__try {
		return call_apply_symbol_proto(job) ? 0u : 0xC0000FFEu;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}

struct symbol_cc_job_t {
	ghidra::Funcdata*   fd = nullptr;
	ghidra::ProtoModel* model = nullptr;
	bool                applied = false;
};

__declspec(noinline) static bool call_apply_symbol_cc(symbol_cc_job_t* job)
{
	try {
		if (!job || !job->fd || !job->model)
			return false;
		ghidra::FuncProto& fp = job->fd->getFuncProto();
		fp.setModel(job->model);
		fp.setModelLock(true);
		job->applied = true;
		return true;
	} catch (...) {
		return false;
	}
}

__declspec(noinline) static DWORD seh_apply_symbol_cc(symbol_cc_job_t* job)
{
	__try {
		return call_apply_symbol_cc(job) ? 0u : 0xC0000FFEu;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}

}

__declspec(noinline) static void call_set_noreturn(ghidra::Funcdata* fd)
{
	fd->getFuncProto().setNoReturn(true);
}

__declspec(noinline) static DWORD seh_set_noreturn(ghidra::Funcdata* fd)
{
	__try {
		call_set_noreturn(fd);
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
}

__declspec(noinline) static ghidra::Funcdata* call_query_function(ghidra::Scope* gscope, ghidra::AddrSpace* space, uint64_t va)
{
	ghidra::Address addr(space, va);
	return gscope->queryFunction(addr);
}

struct query_func_args_t {
	ghidra::Scope*       gscope;
	ghidra::AddrSpace*   space;
	uint64_t             va;
	ghidra::Funcdata*    out;
};

__declspec(noinline) static DWORD seh_run_query_function(query_func_args_t* a)
{
	__try {
		a->out = call_query_function(a->gscope, a->space, a->va);
		return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		a->out = nullptr;
		return GetExceptionCode();
	}
}

inline ghidra::Funcdata* seh_query_function(ghidra::Scope* gscope, ghidra::AddrSpace* space, uint64_t va)
{
	query_func_args_t a{ gscope, space, va, nullptr };
	seh_run_query_function(&a);
	return a.out;
}

void architecture_t::apply_pdb_function_prototypes()
{
	if (!symboltab) {
		diag::log_tagged_critical("dec_pdb", "apply_pdb_function_prototypes_exit reason=no_symtab");
		return;
	}
	ghidra::Scope* gscope = symboltab->getGlobalScope();
	if (!gscope) {
		diag::log_tagged_critical("dec_pdb", "apply_pdb_function_prototypes_exit reason=no_global_scope");
		return;
	}
	ghidra::AddrSpace* space = getDefaultCodeSpace();
	if (!space) {
		diag::log_tagged_critical("dec_pdb", "apply_pdb_function_prototypes_exit reason=no_code_space");
		return;
	}

	std::lock_guard<std::mutex> glk(apply_pdb_global_mutex());

	auto t_start = std::chrono::steady_clock::now();

	struct proto_target_t {
		uint64_t                 address = 0;
		std::string              name;
		std::string              calling_convention;
		bool                     is_noreturn = false;
		parsed_signature_t       signature;
	};
	std::vector<proto_target_t> targets;
	targets.reserve(symbol_db_.symbols.size());
	for (auto& s : symbol_db_.symbols) {
		if (s.kind != symbol_kind_t::function && s.kind != symbol_kind_t::export_)
			continue;
		if (s.module_name.empty()) continue;
		if (s.address == 0) continue;
		proto_target_t target;
		target.address = s.address;
		target.name = !s.display_name.empty() ? s.display_name : s.name;
		target.calling_convention = s.calling_convention;
		target.is_noreturn = s.is_noreturn;
		target.signature = parse_symbol_signature(target.name);
		targets.push_back(std::move(target));
	}

	size_t proto_attempted = 0;
	for (const auto& t : targets) {
		if (t.signature.valid || !t.calling_convention.empty())
			++proto_attempted;
	}

	diag::log_tagged_critical_fmt("dec_pdb",
		"apply_pdb_function_prototypes_enter candidates=%zu proto_candidates=%zu",
		targets.size(), proto_attempted);

	size_t applied = 0;
	size_t not_found = 0;
	size_t failed_set = 0;
	size_t proto_applied = 0;
	size_t proto_failed = 0;
	size_t proto_unresolved = 0;
	size_t cc_applied = 0;

	tl_current_apply_stage = "func_proto";
	for (auto& t : targets) {
		tl_current_apply_name = t.name;
		ghidra::Funcdata* fd = seh_query_function(gscope, space, t.address);
		if (!fd) { ++not_found; continue; }
		if (t.signature.valid) {
			ghidra::ProtoModel* model = nullptr;
			if (!t.signature.calling_convention.empty())
				model = proto_model_from_cc(t.signature.calling_convention);
			if (!model && !t.calling_convention.empty())
				model = proto_model_from_cc(t.calling_convention);
			symbol_proto_job_t job;
			job.arch = this;
			job.fd = fd;
			job.sig = &t.signature;
			job.cc_model = model;
			const DWORD code = seh_apply_symbol_proto(&job);
			if (code != 0 || !job.applied) {
				if (job.unresolved)
					++proto_unresolved;
				else
					++proto_failed;
				if (code != 0 && code != 0xC0000FFEu) {
					diag::log_tagged_critical_fmt("dec_pdb",
						"apply_pdb_function_prototypes_seh_fault stage=func_proto_apply name=%s addr=0x%llx code=0x%08X",
						t.name.c_str(),
						static_cast<unsigned long long>(t.address),
						code);
				}
			} else {
				++proto_applied;
			}
		} else if (!t.calling_convention.empty()) {
			ghidra::ProtoModel* model = proto_model_from_cc(t.calling_convention);
			if (model) {
				symbol_cc_job_t job;
				job.fd = fd;
				job.model = model;
				const DWORD code = seh_apply_symbol_cc(&job);
				if (code != 0 || !job.applied) {
					++proto_failed;
					if (code != 0 && code != 0xC0000FFEu) {
						diag::log_tagged_critical_fmt("dec_pdb",
							"apply_pdb_function_prototypes_seh_fault stage=func_proto_cc name=%s addr=0x%llx code=0x%08X",
							t.name.c_str(),
							static_cast<unsigned long long>(t.address),
							code);
					}
				} else {
					++cc_applied;
				}
			}
		}
		if (!t.is_noreturn)
			continue;
		DWORD code = seh_set_noreturn(fd);
		if (code != 0) {
			diag::log_tagged_critical_fmt("dec_pdb",
				"apply_pdb_function_prototypes_seh_fault stage=func_proto name=%s addr=0x%llx code=0x%08X",
				t.name.c_str(),
				static_cast<unsigned long long>(t.address),
				code);
			++failed_set;
			continue;
		}
		++applied;
	}

	tl_current_apply_stage = "idle";
	tl_current_apply_name.clear();

	auto t_end = std::chrono::steady_clock::now();
	auto dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();

	diag::log_tagged_critical_fmt("dec_pdb",
		"apply_pdb_function_prototypes_exit candidates=%zu applied=%zu not_found=%zu failed_set=%zu proto_attempted=%zu proto_applied=%zu proto_failed=%zu proto_unresolved=%zu cc_applied=%zu duration_ms=%lld",
		targets.size(), applied, not_found, failed_set,
		proto_attempted, proto_applied, proto_failed, proto_unresolved, cc_applied,
		static_cast<long long>(dur_ms));
}

}
