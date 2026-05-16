#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "aida_architecture.hpp"
#include "aida_load_image.hpp"
#include "aida_scope.hpp"
#include "aida_comment_database.hpp"

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

}

architecture_t::architecture_t(const std::string& target,
                               std::ostream* err_stream)
	: ghidra::SleighArchitecture("aida_program", target, err_stream)
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

void architecture_t::buildLoader(ghidra::DocumentStorage& /*store*/)
{
	collectSpecFiles(*errorstream);
	if (staged_loader_) {
		auto raw = staged_loader_.release();
		raw->set_address_space_manager(this);
		loader = raw;
		owns_loader_ = true;
	}
}

ghidra::Scope* architecture_t::buildDatabase(ghidra::DocumentStorage& /*store*/)
{
	symboltab = new ghidra::Database(this, false);
	auto* gscope = new scope_t(this);
	symboltab->attachScope(gscope, nullptr);
	return gscope;
}

void architecture_t::buildTypegrp(ghidra::DocumentStorage& /*store*/)
{
	types = new ghidra::TypeFactory(this);
}

void architecture_t::buildCoreTypes(ghidra::DocumentStorage& /*store*/)
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

void architecture_t::buildCommentDB(ghidra::DocumentStorage& /*store*/)
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

	std::vector<std::pair<uint64_t, std::string>> targets;
	targets.reserve(symbol_db_.symbols.size());
	for (auto& s : symbol_db_.symbols) {
		if (s.kind != symbol_kind_t::function && s.kind != symbol_kind_t::export_)
			continue;
		if (s.module_name.empty()) continue;
		if (s.address == 0) continue;
		if (!s.is_noreturn) continue;
		std::string nm = !s.display_name.empty() ? s.display_name : s.name;
		targets.emplace_back(s.address, nm);
	}

	diag::log_tagged_critical_fmt("dec_pdb",
		"apply_pdb_function_prototypes_enter candidates=%zu",
		targets.size());

	size_t applied = 0;
	size_t not_found = 0;
	size_t failed_set = 0;

	tl_current_apply_stage = "func_proto";
	for (auto& kv : targets) {
		tl_current_apply_name = kv.second;
		ghidra::Funcdata* fd = seh_query_function(gscope, space, kv.first);
		if (!fd) { ++not_found; continue; }
		DWORD code = seh_set_noreturn(fd);
		if (code != 0) {
			diag::log_tagged_critical_fmt("dec_pdb",
				"apply_pdb_function_prototypes_seh_fault stage=func_proto name=%s addr=0x%llx code=0x%08X",
				kv.second.c_str(),
				static_cast<unsigned long long>(kv.first),
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
		"apply_pdb_function_prototypes_exit candidates=%zu applied=%zu not_found=%zu failed_set=%zu duration_ms=%lld",
		targets.size(), applied, not_found, failed_set,
		static_cast<long long>(dur_ms));
}

}
