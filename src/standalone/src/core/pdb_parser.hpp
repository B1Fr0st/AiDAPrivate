#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace pdb_parser {

struct pdb_symbol_t {
	std::string name;
	uint64_t    rva = 0;
	uint32_t    type_index = 0;
	uint32_t    size = 0;
	bool        is_function = false;
};

struct struct_member_t {
	std::string name;
	std::string type_name;
	uint64_t    offset = 0;
	uint64_t    size = 0;
	uint32_t    type_index = 0;
	int         bit_offset = -1;
	int         bit_size = -1;
	bool        is_pointer = false;
	int         pointer_depth = 0;
	bool        is_array = false;
	int         array_count = 0;
};

struct struct_def_t {
	std::string name;
	uint64_t    size = 0;
	uint32_t    type_index = 0;
	bool        is_union = false;
	std::vector<struct_member_t> members;
};

struct enum_member_t {
	std::string name;
	int64_t     value = 0;
};

struct enum_def_t {
	std::string name;
	uint32_t    type_index = 0;
	std::vector<enum_member_t> members;
};

struct pdb_info_t {
	std::string                        file_path;
	std::string                        module_name;
	std::vector<pdb_symbol_t>          symbols;
	std::vector<struct_def_t>          structs;
	std::vector<enum_def_t>            enums;
	std::unordered_map<std::string, size_t> symbol_by_name;
	std::unordered_map<uint64_t, size_t>    symbol_by_rva;
	std::unordered_map<std::string, size_t> struct_by_name;
	std::unordered_map<uint32_t, size_t>    struct_by_ti;
	bool loaded = false;
};

typedef BOOL (WINAPI *fn_SymInitializeW)(HANDLE, PCWSTR, BOOL);
typedef BOOL (WINAPI *fn_SymCleanup)(HANDLE);
typedef DWORD64 (WINAPI *fn_SymLoadModuleExW)(HANDLE, HANDLE, PCWSTR, PCWSTR, DWORD64, DWORD, void*, DWORD);
typedef BOOL (WINAPI *fn_SymUnloadModule64)(HANDLE, DWORD64);
typedef BOOL (WINAPI *fn_SymSetSearchPathW)(HANDLE, PCWSTR);
typedef DWORD (WINAPI *fn_SymSetOptions)(DWORD);
typedef DWORD (WINAPI *fn_SymGetOptions)();

#pragma pack(push, 8)
struct SYMBOL_INFOW_EX {
	ULONG   SizeOfStruct;
	ULONG   TypeIndex;
	ULONG64 Reserved[2];
	ULONG   Index;
	ULONG   Size;
	ULONG64 ModBase;
	ULONG   Flags;
	ULONG64 Value;
	ULONG64 Address;
	ULONG   Register;
	ULONG   Scope;
	ULONG   Tag;
	ULONG   NameLen;
	ULONG   MaxNameLen;
	WCHAR   Name[1];
};

struct TI_FINDCHILDREN_PARAMS_EX {
	ULONG Count;
	ULONG Start;
	ULONG ChildId[1];
};
#pragma pack(pop)

enum IMAGEHLP_SYMBOL_TYPE_INFO_E {
	TI_GET_SYMTAG = 0,
	TI_GET_SYMNAME = 1,
	TI_GET_LENGTH = 2,
	TI_GET_TYPE = 3,
	TI_FINDCHILDREN = 4,
	TI_GET_DATAKIND = 5,
	TI_GET_ADDRESSOFFSET = 6,
	TI_GET_OFFSET = 7,
	TI_GET_VALUE = 8,
	TI_GET_COUNT = 9,
	TI_GET_CHILDRENCOUNT = 10,
	TI_GET_BITPOSITION = 11,
	TI_GET_VIRTUALBASECLASS = 12,
	TI_GET_TYPEID = 13,
	TI_GET_BASETYPE = 14,
	TI_GET_ARRAYINDEXTYPEID = 15,
	TI_FINDCHILDREN_EX = 16,
	TI_GET_NESTED = 18,
	TI_GET_SYMINDEX = 19,
	TI_GET_LEXICALPARENT = 20,
	TI_GET_CLASSPARENTID = 21,
	TI_GET_UDTKIND = 24,
};

enum SymTagEnum_E {
	SymTagNull = 0,
	SymTagExe = 1,
	SymTagCompiland = 2,
	SymTagFunction = 5,
	SymTagData = 7,
	SymTagUDT = 11,
	SymTagEnum = 12,
	SymTagFunctionType = 13,
	SymTagPointerType = 14,
	SymTagArrayType = 15,
	SymTagBaseType = 16,
	SymTagTypedef = 17,
	SymTagBaseClass = 18,
};

enum BasicType_E {
	btNoType = 0,
	btVoid = 1,
	btChar = 2,
	btWChar = 3,
	btInt = 6,
	btUInt = 7,
	btFloat = 8,
	btBool = 10,
	btLong = 13,
	btULong = 14,
	btHresult = 31,
};

typedef BOOL (WINAPI *fn_SymEnumSymbolsExW)(HANDLE, ULONG64, PCWSTR,
    BOOL (CALLBACK*)(SYMBOL_INFOW_EX*, ULONG, void*), void*, DWORD);
typedef BOOL (WINAPI *fn_SymGetTypeInfo)(HANDLE, DWORD64, ULONG,
    IMAGEHLP_SYMBOL_TYPE_INFO_E, void*);
typedef BOOL (WINAPI *fn_SymEnumTypesW)(HANDLE, ULONG64, PCWSTR,
    BOOL (CALLBACK*)(SYMBOL_INFOW_EX*, ULONG, void*), void*);

struct dbghelp_api_t {
	HMODULE                 hmod = nullptr;
	fn_SymInitializeW       pSymInitializeW = nullptr;
	fn_SymCleanup           pSymCleanup = nullptr;
	fn_SymLoadModuleExW     pSymLoadModuleExW = nullptr;
	fn_SymUnloadModule64    pSymUnloadModule64 = nullptr;
	fn_SymSetSearchPathW    pSymSetSearchPathW = nullptr;
	fn_SymSetOptions        pSymSetOptions = nullptr;
	fn_SymGetOptions        pSymGetOptions = nullptr;
	fn_SymEnumSymbolsExW    pSymEnumSymbolsExW = nullptr;
	fn_SymGetTypeInfo       pSymGetTypeInfo = nullptr;
	fn_SymEnumTypesW        pSymEnumTypesW = nullptr;

	bool loaded = false;
};

inline dbghelp_api_t g_api;
inline std::mutex g_api_mutex;

inline bool load_dbghelp()
{
	std::lock_guard<std::mutex> lk(g_api_mutex);
	if (g_api.loaded) return true;

	g_api.hmod = LoadLibraryW(L"dbghelp.dll");
	if (!g_api.hmod) return false;

	auto gp = [&](const char* name) -> FARPROC {
		return GetProcAddress(g_api.hmod, name);
	};

	g_api.pSymInitializeW    = reinterpret_cast<fn_SymInitializeW>(gp("SymInitializeW"));
	g_api.pSymCleanup        = reinterpret_cast<fn_SymCleanup>(gp("SymCleanup"));
	g_api.pSymLoadModuleExW  = reinterpret_cast<fn_SymLoadModuleExW>(gp("SymLoadModuleExW"));
	g_api.pSymUnloadModule64 = reinterpret_cast<fn_SymUnloadModule64>(gp("SymUnloadModule64"));
	g_api.pSymSetSearchPathW = reinterpret_cast<fn_SymSetSearchPathW>(gp("SymSetSearchPathW"));
	g_api.pSymSetOptions     = reinterpret_cast<fn_SymSetOptions>(gp("SymSetOptions"));
	g_api.pSymGetOptions     = reinterpret_cast<fn_SymGetOptions>(gp("SymGetOptions"));
	g_api.pSymEnumSymbolsExW = reinterpret_cast<fn_SymEnumSymbolsExW>(gp("SymEnumSymbolsExW"));
	g_api.pSymGetTypeInfo    = reinterpret_cast<fn_SymGetTypeInfo>(gp("SymGetTypeInfo"));
	g_api.pSymEnumTypesW     = reinterpret_cast<fn_SymEnumTypesW>(gp("SymEnumTypesW"));

	if (!g_api.pSymInitializeW || !g_api.pSymCleanup || !g_api.pSymLoadModuleExW ||
	    !g_api.pSymEnumSymbolsExW || !g_api.pSymGetTypeInfo) {
		FreeLibrary(g_api.hmod);
		g_api.hmod = nullptr;
		return false;
	}

	g_api.loaded = true;
	return true;
}

namespace detail {

inline std::string wstr_to_utf8(const wchar_t* ws)
{
	if (!ws || !*ws) return {};
	int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
	if (len <= 0) return {};
	std::string out(len - 1, '\0');
	WideCharToMultiByte(CP_UTF8, 0, ws, -1, out.data(), len, nullptr, nullptr);
	return out;
}

inline std::wstring utf8_to_wstr(const std::string& s)
{
	if (s.empty()) return {};
	int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
	if (len <= 0) return {};
	std::wstring out(len - 1, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), len);
	return out;
}

inline std::string get_base_type_name(BasicType_E bt, uint64_t length)
{
	switch (bt) {
	case btVoid:   return "void";
	case btChar:   return "char";
	case btWChar:  return "wchar_t";
	case btBool:   return "bool";
	case btFloat:  return (length == 4) ? "float" : "double";
	case btHresult: return "HRESULT";
	case btInt:
		switch (length) {
		case 1: return "int8_t";
		case 2: return "int16_t";
		case 4: return "int32_t";
		case 8: return "int64_t";
		default: return "int";
		}
	case btUInt:
		switch (length) {
		case 1: return "uint8_t";
		case 2: return "uint16_t";
		case 4: return "uint32_t";
		case 8: return "uint64_t";
		default: return "unsigned int";
		}
	case btLong:
		return (length == 8) ? "int64_t" : "long";
	case btULong:
		return (length == 8) ? "uint64_t" : "unsigned long";
	default:
		char buf[32];
		snprintf(buf, sizeof(buf), "unk_%llu", static_cast<unsigned long long>(length));
		return buf;
	}
}

inline std::string resolve_type_name(HANDLE hProc, DWORD64 modBase, ULONG typeIndex)
{
	DWORD tag = 0;
	if (!g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_SYMTAG, &tag))
		return "unk";

	switch (tag) {
	case SymTagBaseType: {
		DWORD bt = 0;
		ULONG64 len = 0;
		g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_BASETYPE, &bt);
		g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_LENGTH, &len);
		return get_base_type_name(static_cast<BasicType_E>(bt), len);
	}
	case SymTagPointerType: {
		DWORD innerTypeId = 0;
		if (g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_TYPEID, &innerTypeId)) {
			return resolve_type_name(hProc, modBase, innerTypeId) + "*";
		}
		return "void*";
	}
	case SymTagArrayType: {
		DWORD elemTypeId = 0;
		DWORD count = 0;
		g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_TYPEID, &elemTypeId);
		g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_COUNT, &count);
		char buf[16];
		snprintf(buf, sizeof(buf), "[%u]", count);
		return resolve_type_name(hProc, modBase, elemTypeId) + buf;
	}
	case SymTagUDT:
	case SymTagEnum:
	case SymTagTypedef: {
		WCHAR* pName = nullptr;
		if (g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_SYMNAME, &pName) && pName) {
			std::string name = wstr_to_utf8(pName);
			LocalFree(pName);
			return name;
		}
		return "unk_udt";
	}
	case SymTagFunctionType:
		return "fn_ptr";
	default: {
		char buf[32];
		snprintf(buf, sizeof(buf), "tag_%u", tag);
		return buf;
	}
	}
}

struct sym_enum_ctx_t {
	HANDLE                      hProc;
	DWORD64                     modBase;
	std::vector<pdb_symbol_t>*  symbols;
};

inline BOOL CALLBACK sym_enum_callback(SYMBOL_INFOW_EX* pSymInfo, ULONG symSize, void* ctx)
{
	(void)symSize;
	auto* c = static_cast<sym_enum_ctx_t*>(ctx);

	pdb_symbol_t sym;
	sym.name = wstr_to_utf8(pSymInfo->Name);
	sym.rva = static_cast<uint64_t>(pSymInfo->Address - pSymInfo->ModBase);
	sym.type_index = pSymInfo->TypeIndex;
	sym.size = pSymInfo->Size;
	sym.is_function = (pSymInfo->Tag == SymTagFunction);

	c->symbols->push_back(std::move(sym));
	return TRUE;
}

struct type_enum_ctx_t {
	HANDLE                      hProc;
	DWORD64                     modBase;
	std::vector<ULONG>          udt_indices;
	std::vector<ULONG>          enum_indices;
};

inline BOOL CALLBACK type_enum_callback(SYMBOL_INFOW_EX* pSymInfo, ULONG symSize, void* ctx)
{
	(void)symSize;
	auto* c = static_cast<type_enum_ctx_t*>(ctx);

	if (pSymInfo->Tag == SymTagUDT)
		c->udt_indices.push_back(pSymInfo->TypeIndex);
	else if (pSymInfo->Tag == SymTagEnum)
		c->enum_indices.push_back(pSymInfo->TypeIndex);

	return TRUE;
}

inline void import_struct_members(HANDLE hProc, DWORD64 modBase, ULONG typeIndex, struct_def_t& def)
{
	DWORD childCount = 0;
	if (!g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_CHILDRENCOUNT, &childCount) || childCount == 0)
		return;

	size_t alloc_sz = sizeof(TI_FINDCHILDREN_PARAMS_EX) + (childCount - 1) * sizeof(ULONG);
	std::vector<uint8_t> buf(alloc_sz, 0);
	auto* fc = reinterpret_cast<TI_FINDCHILDREN_PARAMS_EX*>(buf.data());
	fc->Count = childCount;
	fc->Start = 0;

	if (!g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_FINDCHILDREN, fc))
		return;

	for (ULONG i = 0; i < childCount; ++i) {
		ULONG childId = fc->ChildId[i];
		DWORD tag = 0;
		g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_SYMTAG, &tag);

		if (tag != SymTagData) continue;

		struct_member_t member;

		WCHAR* pName = nullptr;
		if (g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_SYMNAME, &pName) && pName) {
			member.name = wstr_to_utf8(pName);
			LocalFree(pName);
		}

		DWORD offset = 0;
		g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_OFFSET, &offset);
		member.offset = offset;

		DWORD memTypeId = 0;
		if (g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_TYPEID, &memTypeId)) {
			member.type_index = memTypeId;
			member.type_name = resolve_type_name(hProc, modBase, memTypeId);

			ULONG64 memLen = 0;
			g_api.pSymGetTypeInfo(hProc, modBase, memTypeId, TI_GET_LENGTH, &memLen);
			member.size = memLen;

			DWORD memTag = 0;
			g_api.pSymGetTypeInfo(hProc, modBase, memTypeId, TI_GET_SYMTAG, &memTag);

			if (memTag == SymTagPointerType) {
				member.is_pointer = true;
				member.pointer_depth = 1;
				DWORD inner = memTypeId;
				for (int d = 0; d < 8; ++d) {
					DWORD next = 0;
					if (!g_api.pSymGetTypeInfo(hProc, modBase, inner, TI_GET_TYPEID, &next)) break;
					DWORD nextTag = 0;
					g_api.pSymGetTypeInfo(hProc, modBase, next, TI_GET_SYMTAG, &nextTag);
					if (nextTag != SymTagPointerType) break;
					member.pointer_depth++;
					inner = next;
				}
			}

			if (memTag == SymTagArrayType) {
				member.is_array = true;
				DWORD count = 0;
				g_api.pSymGetTypeInfo(hProc, modBase, memTypeId, TI_GET_COUNT, &count);
				member.array_count = static_cast<int>(count);
			}
		}

		DWORD bitPos = 0;
		if (g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_BITPOSITION, &bitPos)) {
			member.bit_offset = static_cast<int>(bitPos);
			ULONG64 bitLen = 0;
			g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_LENGTH, &bitLen);
			member.bit_size = static_cast<int>(bitLen);
		}

		def.members.push_back(std::move(member));
	}

	std::sort(def.members.begin(), def.members.end(),
	          [](const struct_member_t& a, const struct_member_t& b) { return a.offset < b.offset; });
}

inline void import_enum_members(HANDLE hProc, DWORD64 modBase, ULONG typeIndex, enum_def_t& def)
{
	DWORD childCount = 0;
	if (!g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_GET_CHILDRENCOUNT, &childCount) || childCount == 0)
		return;

	size_t alloc_sz = sizeof(TI_FINDCHILDREN_PARAMS_EX) + (childCount - 1) * sizeof(ULONG);
	std::vector<uint8_t> buf(alloc_sz, 0);
	auto* fc = reinterpret_cast<TI_FINDCHILDREN_PARAMS_EX*>(buf.data());
	fc->Count = childCount;
	fc->Start = 0;

	if (!g_api.pSymGetTypeInfo(hProc, modBase, typeIndex, TI_FINDCHILDREN, fc))
		return;

	for (ULONG i = 0; i < childCount; ++i) {
		ULONG childId = fc->ChildId[i];
		enum_member_t em;

		WCHAR* pName = nullptr;
		if (g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_SYMNAME, &pName) && pName) {
			em.name = wstr_to_utf8(pName);
			LocalFree(pName);
		}

		VARIANT val;
		VariantInit(&val);
		if (g_api.pSymGetTypeInfo(hProc, modBase, childId, TI_GET_VALUE, &val)) {
			switch (val.vt) {
			case VT_I1:  em.value = val.cVal; break;
			case VT_I2:  em.value = val.iVal; break;
			case VT_I4:  em.value = val.lVal; break;
			case VT_I8:  em.value = val.llVal; break;
			case VT_UI1: em.value = val.bVal; break;
			case VT_UI2: em.value = val.uiVal; break;
			case VT_UI4: em.value = val.ulVal; break;
			case VT_UI8: em.value = static_cast<int64_t>(val.ullVal); break;
			default: break;
			}
			VariantClear(&val);
		}

		def.members.push_back(std::move(em));
	}
}

}

inline bool parse_pdb(const std::string& pdb_path,
                      const std::string& symbol_search_path,
                      pdb_info_t& out,
                      std::atomic<float>* progress = nullptr,
                      std::atomic<bool>* cancel = nullptr)
{
	if (!load_dbghelp()) return false;

	out = {};
	out.file_path = pdb_path;

	auto stem = std::filesystem::path(pdb_path).stem().string();
	out.module_name = stem;

	HANDLE hFakeProc = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(GetCurrentProcessId() ^ 0xABCD0000));

	DWORD opts = g_api.pSymGetOptions ? g_api.pSymGetOptions() : 0;
	opts |= 0x00000004;
	opts |= 0x00000010;
	opts |= 0x00000200;
	opts &= ~0x00000001;
	if (g_api.pSymSetOptions) g_api.pSymSetOptions(opts);

	std::wstring wSearchPath = detail::utf8_to_wstr(symbol_search_path);
	if (!g_api.pSymInitializeW(hFakeProc, wSearchPath.empty() ? nullptr : wSearchPath.c_str(), FALSE))
		return false;

	if (!wSearchPath.empty() && g_api.pSymSetSearchPathW)
		g_api.pSymSetSearchPathW(hFakeProc, wSearchPath.c_str());

	std::wstring wPdbPath = detail::utf8_to_wstr(pdb_path);
	DWORD64 modBase = g_api.pSymLoadModuleExW(hFakeProc, nullptr, wPdbPath.c_str(), nullptr,
	                                           0x10000000, 0x01000000, nullptr, 0);
	if (!modBase) {
		g_api.pSymCleanup(hFakeProc);
		return false;
	}

	if (progress) progress->store(0.1f);

	detail::sym_enum_ctx_t symCtx;
	symCtx.hProc = hFakeProc;
	symCtx.modBase = modBase;
	symCtx.symbols = &out.symbols;

	g_api.pSymEnumSymbolsExW(hFakeProc, modBase, L"*", detail::sym_enum_callback, &symCtx, 0);

	if (progress) progress->store(0.4f);
	if (cancel && cancel->load()) {
		g_api.pSymUnloadModule64(hFakeProc, modBase);
		g_api.pSymCleanup(hFakeProc);
		return false;
	}

	for (size_t i = 0; i < out.symbols.size(); ++i) {
		out.symbol_by_name[out.symbols[i].name] = i;
		out.symbol_by_rva[out.symbols[i].rva] = i;
	}

	if (progress) progress->store(0.5f);

	detail::type_enum_ctx_t typeCtx;
	typeCtx.hProc = hFakeProc;
	typeCtx.modBase = modBase;

	if (g_api.pSymEnumTypesW)
		g_api.pSymEnumTypesW(hFakeProc, modBase, L"*", detail::type_enum_callback, &typeCtx);

	if (progress) progress->store(0.6f);

	size_t total_types = typeCtx.udt_indices.size() + typeCtx.enum_indices.size();
	size_t processed = 0;

	for (ULONG ti : typeCtx.udt_indices) {
		if (cancel && cancel->load()) break;

		struct_def_t def;
		def.type_index = ti;

		WCHAR* pName = nullptr;
		if (g_api.pSymGetTypeInfo(hFakeProc, modBase, ti, TI_GET_SYMNAME, &pName) && pName) {
			def.name = detail::wstr_to_utf8(pName);
			LocalFree(pName);
		}

		ULONG64 length = 0;
		g_api.pSymGetTypeInfo(hFakeProc, modBase, ti, TI_GET_LENGTH, &length);
		def.size = length;

		DWORD udtKind = 0;
		g_api.pSymGetTypeInfo(hFakeProc, modBase, ti, TI_GET_UDTKIND, &udtKind);
		def.is_union = (udtKind == 1);

		detail::import_struct_members(hFakeProc, modBase, ti, def);

		if (!def.name.empty()) {
			out.struct_by_name[def.name] = out.structs.size();
			out.struct_by_ti[def.type_index] = out.structs.size();
		}
		out.structs.push_back(std::move(def));

		++processed;
		if (progress && total_types > 0)
			progress->store(0.6f + 0.35f * (static_cast<float>(processed) / static_cast<float>(total_types)));
	}

	for (ULONG ti : typeCtx.enum_indices) {
		if (cancel && cancel->load()) break;

		enum_def_t def;
		def.type_index = ti;

		WCHAR* pName = nullptr;
		if (g_api.pSymGetTypeInfo(hFakeProc, modBase, ti, TI_GET_SYMNAME, &pName) && pName) {
			def.name = detail::wstr_to_utf8(pName);
			LocalFree(pName);
		}

		detail::import_enum_members(hFakeProc, modBase, ti, def);
		out.enums.push_back(std::move(def));

		++processed;
		if (progress && total_types > 0)
			progress->store(0.6f + 0.35f * (static_cast<float>(processed) / static_cast<float>(total_types)));
	}

	g_api.pSymUnloadModule64(hFakeProc, modBase);
	g_api.pSymCleanup(hFakeProc);

	out.loaded = true;
	if (progress) progress->store(1.f);
	return true;
}

inline std::string struct_to_cpp(const struct_def_t& def)
{
	std::string out;
	out += def.is_union ? "union " : "struct ";
	out += def.name;
	out += " {\n";

	uint64_t last_end = 0;
	int pad_idx = 0;

	for (auto& m : def.members) {
		if (m.offset > last_end) {
			uint64_t gap = m.offset - last_end;
			char buf[64];
			snprintf(buf, sizeof(buf), "    uint8_t _pad%d[%llu];\n", pad_idx++,
			         static_cast<unsigned long long>(gap));
			out += buf;
		}

		if (m.bit_size >= 0) {
			char buf[128];
			snprintf(buf, sizeof(buf), "    %s %s : %d;\n",
			         m.type_name.c_str(), m.name.c_str(), m.bit_size);
			out += buf;
		} else if (m.is_array) {
			char buf[128];
			snprintf(buf, sizeof(buf), "    %s %s[%d];\n",
			         m.type_name.c_str(), m.name.c_str(), m.array_count);
			out += buf;
		} else {
			char buf[128];
			snprintf(buf, sizeof(buf), "    %s %s;\n",
			         m.type_name.c_str(), m.name.c_str());
			out += buf;
		}

		last_end = m.offset + m.size;
	}

	if (last_end < def.size) {
		uint64_t gap = def.size - last_end;
		char buf[64];
		snprintf(buf, sizeof(buf), "    uint8_t _pad%d[%llu];\n", pad_idx,
		         static_cast<unsigned long long>(gap));
		out += buf;
	}

	char size_comment[64];
	snprintf(size_comment, sizeof(size_comment), "}; // size: 0x%llX (%llu bytes)\n",
	         static_cast<unsigned long long>(def.size), static_cast<unsigned long long>(def.size));
	out += size_comment;
	return out;
}

}
