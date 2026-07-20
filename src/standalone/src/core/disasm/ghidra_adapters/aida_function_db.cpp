#include "aida_function_db.hpp"
#if !defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
#include "../zydis_disasm.hpp"
#include "../../analysis/symbol_store.hpp"
#include "standalone_driver.hpp"
#endif

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <mutex>
#include <new>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace aida_ghidra {

void function_db_t::clear()
{
	symbols.clear();
	by_address.clear();
	by_name.clear();
	image_base = 0;
	image_size = 0;
	is_pe = false;
	is_64bit = true;
}

namespace {

inline bool name_is_safe_for_index(const std::string& n)
{
	if (n.empty()) return false;
	if (n.size() > 1024) return false;
	for (size_t i = 0; i < n.size(); ++i) {
		unsigned char c = static_cast<unsigned char>(n[i]);
		if (c == 0) return false;
		if (c < 0x20) return false;
	}
	return true;
}

}

void function_db_t::add_symbol(symbol_record_t rec)
{
	if (rec.address == 0)
		return;

	auto it = by_address.find(rec.address);
	if (it != by_address.end()) {
		auto& existing = symbols[it->second];
		const auto is_code_kind = [](symbol_kind_t kind) {
			return kind == symbol_kind_t::function || kind == symbol_kind_t::import ||
				kind == symbol_kind_t::export_;
		};
		const bool promote_to_code = is_code_kind(rec.kind) &&
			!is_code_kind(existing.kind);
		if (promote_to_code ||
			(existing.kind == symbol_kind_t::unknown && rec.kind != symbol_kind_t::unknown))
			existing.kind = rec.kind;
		if ((existing.name.empty() || promote_to_code) && !rec.name.empty()) {
			existing.name = rec.name;
			if (name_is_safe_for_index(existing.name))
				by_name[existing.name] = it->second;
		}
		if ((existing.display_name.empty() || promote_to_code) && !rec.display_name.empty())
			existing.display_name = rec.display_name;
		if (rec.is_external)
			existing.is_external = true;
		if (rec.is_thunk)
			existing.is_thunk = true;
		if (rec.is_noreturn)
			existing.is_noreturn = true;
		if (existing.module_name.empty() && !rec.module_name.empty())
			existing.module_name = rec.module_name;
		if (existing.calling_convention.empty() && !rec.calling_convention.empty())
			existing.calling_convention = rec.calling_convention;
		if (promote_to_code)
			existing.size = rec.size;
		else if (rec.size > existing.size)
			existing.size = rec.size;
		return;
	}

	size_t index = symbols.size();
	by_address[rec.address] = index;
	if (name_is_safe_for_index(rec.name))
		by_name[rec.name] = index;
	symbols.push_back(std::move(rec));
}

const symbol_record_t* function_db_t::find_by_address(uint64_t addr) const
{
	auto it = by_address.find(addr);
	if (it == by_address.end())
		return nullptr;
	return &symbols[it->second];
}

const symbol_record_t* function_db_t::find_containing(uint64_t addr) const
{
	const symbol_record_t* best = nullptr;
	uint64_t best_size = UINT64_MAX;
	for (auto& s : symbols) {
		if (s.size == 0)
			continue;
		if (addr >= s.address && addr - s.address < s.size) {
			if (s.size < best_size) {
				best = &s;
				best_size = s.size;
			}
		}
	}
	return best;
}

const symbol_record_t* function_db_t::find_by_name(const std::string& name) const
{
	auto it = by_name.find(name);
	if (it == by_name.end())
		return nullptr;
	return &symbols[it->second];
}

bool function_db_t::address_in_image(uint64_t addr) const
{
	if (image_base == 0 || image_size == 0)
		return false;
	return addr >= image_base && addr - image_base < image_size;
}

namespace {

std::string sanitize_symbol_name(const std::string& raw)
{
	std::string out;
	out.reserve(raw.size());
	for (char c : raw) {
		unsigned char uc = static_cast<unsigned char>(c);
		if (std::isalnum(uc) || c == '_')
			out.push_back(c);
		else if (c == '@' || c == '?' || c == '$')
			out.push_back('_');
		else
			out.push_back('_');
	}
	if (out.empty())
		return "anon_sym";
	if (std::isdigit(static_cast<unsigned char>(out[0])))
		out.insert(out.begin(), '_');
	return out;
}

bool name_is_noreturn_default(const std::string& name)
{
	static const char* kNoreturn[] = {
		"abort", "_abort", "exit", "_exit",
		"ExitProcess", "ExitThread", "TerminateProcess", "TerminateThread",
		"FatalAppExitA", "FatalAppExitW", "FatalExit",
		"_invoke_watson", "_invalid_parameter_noinfo_noreturn",
		"longjmp", "_longjmp", "RaiseException",
		"__cxa_throw", "_CxxThrowException",
		"unhandled_exception", "abort_program",
	};
	for (auto p : kNoreturn) {
		if (name == p)
			return true;
	}
	return false;
}

}

#if defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)

void populate_from_pe(function_db_t&, const DisasmFile&, const pe_parser::pe_info_t*)
{
	throw std::logic_error("isolated native decompiler cannot access application PE state");
}

void populate_from_driver(function_db_t&, uint64_t)
{
	throw std::logic_error("isolated native decompiler cannot access the live driver");
}

void populate_from_symbol_store(function_db_t&)
{
	throw std::logic_error("isolated native decompiler cannot access application symbol state");
}

#else

void populate_from_pe(function_db_t& db,
                      const DisasmFile& file,
                      const pe_parser::pe_info_t* pe_info)
{
	db.clear();

	if (!file.loaded || file.sections.empty())
		return;

	db.image_base = file.image_base;
	uint64_t computed_size = 0;
	for (auto& s : file.sections) {
		uint64_t end = s.va + s.bytes.size();
		uint64_t rel = end > file.image_base ? end - file.image_base : 0;
		if (rel > computed_size)
			computed_size = rel;
	}
	db.image_size = computed_size;
	db.is_pe = true;

	if (pe_info) {
		db.is_64bit = pe_info->is_64bit;

		for (auto& exp : pe_info->exports) {
			symbol_record_t rec;
			rec.address = exp.address ? exp.address : (db.image_base + exp.rva);
			rec.size = 0;
			rec.name = sanitize_symbol_name(exp.name.empty()
				? std::string("ord_") + std::to_string(exp.ordinal)
				: exp.name);
			rec.display_name = exp.name.empty()
				? rec.name
				: exp.name;
			rec.kind = exp.is_forwarded ? symbol_kind_t::import : symbol_kind_t::export_;
			rec.is_external = exp.is_forwarded;
			rec.is_noreturn = !exp.name.empty() && name_is_noreturn_default(exp.name);
			db.add_symbol(std::move(rec));
		}

		for (auto& imp : pe_info->imports) {
			symbol_record_t rec;
			rec.address = imp.iat_address;
			if (rec.address == 0)
				continue;
			std::string base = imp.function_name.empty()
				? std::string("ord_") + std::to_string(imp.ordinal)
				: imp.function_name;
			rec.name = std::string("imp_") + sanitize_symbol_name(base);
			rec.display_name = imp.function_name.empty()
				? base
				: imp.function_name;
			rec.module_name = imp.module_name;
			rec.kind = symbol_kind_t::import;
			rec.is_external = true;
			rec.is_thunk = false;
			rec.is_noreturn = !imp.function_name.empty() && name_is_noreturn_default(imp.function_name);
			db.add_symbol(std::move(rec));
		}

		for (auto& sec : pe_info->sections) {
			if (sec.virtual_address == 0 || sec.virtual_size == 0)
				continue;
			symbol_record_t rec;
			rec.address = db.image_base + sec.virtual_address;
			rec.size = sec.virtual_size;
			rec.name = std::string("sec_") + sanitize_symbol_name(sec.name);
			rec.display_name = sec.name;
			rec.kind = symbol_kind_t::data;
			db.add_symbol(std::move(rec));
		}
	}

	if (file.entry_point != 0) {
		symbol_record_t rec;
		rec.address = file.entry_point;
		rec.name = "entry_point";
		rec.display_name = "entry_point";
		rec.kind = symbol_kind_t::function;
		db.add_symbol(std::move(rec));
	}
}

void populate_from_driver(function_db_t& db, uint64_t module_base)
{
	auto modules = driver_bridge::enumerate_modules();
	for (auto& m : modules) {
		if (module_base == 0 || (module_base >= m.base && module_base < m.base + m.size)) {
			db.image_base = m.base;
			db.image_size = m.size;
			db.is_pe = true;
			break;
		}
	}
}

void populate_from_symbol_store(function_db_t& db)
{
	std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
	for (const auto& kv : symbol_store::g_state.modules) {
		const auto& ms = kv.second;
		if (!ms.pdb.loaded) continue;
		if (ms.base == 0 || ms.size == 0) continue;

		bool image_overlap = true;
		if (db.image_base != 0 && db.image_size != 0) {
			uint64_t image_end = db.image_base + db.image_size;
			uint64_t mod_end = ms.base + ms.size;
			if (mod_end <= db.image_base || ms.base >= image_end)
				image_overlap = false;
		}
		if (!image_overlap) continue;

		for (const auto& sym : ms.pdb.symbols) {
			if (!sym.is_function) continue;
			if (sym.name.empty()) continue;
			if (sym.rva == 0) continue;
			uint64_t va = ms.base + sym.rva;
			if (va == 0) continue;
			if (db.image_base != 0 && db.image_size != 0) {
				if (va < db.image_base || va >= db.image_base + db.image_size)
					continue;
			}
			std::string sanitized = sanitize_symbol_name(sym.name);
			if (sanitized.empty()) continue;
			symbol_record_t rec;
			rec.address = va;
			rec.size = sym.size;
			rec.name = std::move(sanitized);
			rec.display_name = sym.name;
			rec.module_name = ms.module_name;
			rec.kind = symbol_kind_t::function;
			rec.is_external = false;
			rec.is_thunk = false;
			rec.is_noreturn = name_is_noreturn_default(sym.name);
			db.add_symbol(std::move(rec));
		}
	}
}

#endif

#if !defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
namespace {

uint64_t workspace_load_base(
	const aida::analysis::workspace_identity_t& identity,
	const aida::analysis::pe_image_t* image)
{
	if (identity.target_kind() == aida::analysis::target_kind_t::live_snapshot &&
		identity.module())
		return identity.module()->base;
	return image ? image->image_base() : identity.image_base();
}

std::optional<uint64_t> workspace_rva_to_va(
	uint64_t rva,
	const aida::analysis::workspace_identity_t& identity,
	const aida::analysis::pe_image_t* image)
{
	if (image && !image->rva_to_va(rva))
		return std::nullopt;
	const uint64_t base = workspace_load_base(identity, image);
	if (rva > UINT64_MAX - base)
		return std::nullopt;
	return base + rva;
}

std::optional<uint64_t> workspace_address_to_va(
	const aida::analysis::address_t& address,
	const aida::analysis::workspace_identity_t& identity,
	const aida::analysis::pe_image_t* image)
{
	using aida::analysis::address_space_id_t;
	switch (address.space) {
	case address_space_id_t::virtual_address:
	case address_space_id_t::live_virtual:
		return address.value;
	case address_space_id_t::relative_virtual:
		return workspace_rva_to_va(address.value, identity, image);
	case address_space_id_t::file_offset:
		if (!image)
			return std::nullopt;
		{
			auto rva = image->file_offset_to_rva(address.value);
			if (!rva)
				return std::nullopt;
			return workspace_rva_to_va(rva.value(), identity, image);
		}
	}
	return std::nullopt;
}

symbol_kind_t workspace_symbol_kind(aida::analysis::symbol_kind_t kind)
{
	switch (kind) {
	case aida::analysis::symbol_kind_t::function:
	case aida::analysis::symbol_kind_t::debug_symbol:
	case aida::analysis::symbol_kind_t::metadata:
		return symbol_kind_t::function;
	case aida::analysis::symbol_kind_t::import_symbol:
		return symbol_kind_t::import;
	case aida::analysis::symbol_kind_t::export_symbol:
		return symbol_kind_t::export_;
	case aida::analysis::symbol_kind_t::data:
	case aida::analysis::symbol_kind_t::type_symbol:
		return symbol_kind_t::data;
	}
	return symbol_kind_t::unknown;
}

}

void populate_from_workspace(
	function_db_t& db,
	const aida::analysis::workspace_identity_t& identity,
	const aida::analysis::pe_image_t* image,
	const aida::analysis::analysis_snapshot_t* snapshot)
{
	db.clear();
	db.image_base = workspace_load_base(identity, image);
	db.image_size = image ? image->image_size()
		: (identity.module() ? identity.module()->size : 0);
	db.is_pe = image != nullptr;
	db.is_64bit = identity.architecture() == aida::analysis::architecture_id_t::x86_64;

	if (image) {
		for (const auto& item : image->exports()) {
			if (item.rva == 0)
				continue;
			auto address = workspace_rva_to_va(item.rva, identity, image);
			if (!address)
				continue;
			symbol_record_t record;
			record.address = *address;
			record.name = sanitize_symbol_name(item.name.value_or(
				std::string("ord_") + std::to_string(item.ordinal)));
			record.display_name = item.name.value_or(record.name);
			record.kind = item.forwarder ? symbol_kind_t::import : symbol_kind_t::export_;
			record.is_external = item.forwarder.has_value();
			record.is_noreturn = item.name && name_is_noreturn_default(*item.name);
			db.add_symbol(std::move(record));
		}

		for (const auto& item : image->imports()) {
			if (item.iat_rva == 0)
				continue;
			auto address = workspace_rva_to_va(item.iat_rva, identity, image);
			if (!address)
				continue;
			symbol_record_t record;
			record.address = *address;
			const std::string base = item.name.value_or(item.ordinal
				? std::string("ord_") + std::to_string(*item.ordinal)
				: std::string("unknown_import"));
			record.name = std::string("imp_") + sanitize_symbol_name(base);
			record.display_name = base;
			record.module_name = item.library;
			record.kind = symbol_kind_t::import;
			record.is_external = true;
			record.is_noreturn = item.name && name_is_noreturn_default(*item.name);
			db.add_symbol(std::move(record));
		}

		for (const auto& section : image->sections()) {
			if (section.virtual_size == 0)
				continue;
			auto address = workspace_rva_to_va(section.virtual_address, identity, image);
			if (!address)
				continue;
			symbol_record_t record;
			record.address = *address;
			record.size = section.virtual_size;
			record.name = std::string("sec_") + sanitize_symbol_name(section.name);
			record.display_name = section.name;
			record.kind = symbol_kind_t::data;
			db.add_symbol(std::move(record));
		}

		if (image->entry_rva() != 0) {
			auto address = workspace_rva_to_va(image->entry_rva(), identity, image);
			if (address) {
				symbol_record_t record;
				record.address = *address;
				record.name = "entry_point";
				record.display_name = record.name;
				record.kind = symbol_kind_t::function;
				db.add_symbol(std::move(record));
			}
		}
	}

	if (snapshot) {
		for (const auto& item : snapshot->symbols) {
			auto va = workspace_address_to_va(item.address, identity, image);
			if (!va || item.name.empty())
				continue;
			symbol_record_t record;
			record.address = *va;
			record.name = sanitize_symbol_name(item.name);
			record.display_name = item.name;
			record.kind = workspace_symbol_kind(item.kind);
			record.is_external = item.kind == aida::analysis::symbol_kind_t::import_symbol;
			record.is_noreturn = name_is_noreturn_default(item.name);
			db.add_symbol(std::move(record));
		}

		for (const auto& item : snapshot->functions) {
			auto start = workspace_address_to_va(item.start, identity, image);
			auto end = workspace_address_to_va(item.end, identity, image);
			if (!start)
				continue;
			symbol_record_t record;
			record.address = *start;
			record.size = end && *end > *start ? *end - *start : 0;
			record.name = std::string("sub_") + [&]() {
				char text[32]{};
				std::snprintf(text, sizeof(text), "%llx",
					static_cast<unsigned long long>(*start));
				return std::string(text);
			}();
			record.display_name = record.name;
			record.kind = symbol_kind_t::function;
			record.is_thunk = item.thunk;
			record.is_noreturn = item.noreturn;
			db.add_symbol(std::move(record));
		}
	}

	populate_default_noreturn(db);
}

#endif

void populate_default_noreturn(function_db_t& db)
{
	for (auto& s : db.symbols) {
		if (!s.is_noreturn && name_is_noreturn_default(s.display_name.empty() ? s.name : s.display_name))
			s.is_noreturn = true;
	}
}

}

#if !defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
namespace aida::analysis::ghidra_adapter {

namespace {

workspace_result_t<void> stopped(const cancellation_token_t& cancel,
                                 const char* phase) {
    if (!cancel.stop_requested())
        return workspace_result_t<void>::success();
    auto error = make_workspace_error(
        cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                  : workspace_error_code_t::cancelled,
        cancel.deadline_exceeded() ? "Ghidra function database deadline exceeded"
                                  : "Ghidra function database operation cancelled",
        phase);
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return workspace_result_t<void>::failure(std::move(error));
}

workspace_result_t<void> validate_identity(const workspace_identity_t& identity,
                                           const workspace_image_t& image,
                                           const analysis_snapshot_t& snapshot,
                                           const ghidra_adapter_revision_t& revision,
                                           const cancellation_token_t& cancel) {
    auto stop = stopped(cancel, "ghidra.function_db.create");
    if (!stop)
        return stop;
    auto image_valid = validate_workspace_image(image, {}, true, cancel);
    if (!image_valid)
        return image_valid;
    auto snapshot_valid = validate_analysis_snapshot(snapshot, false, cancel);
    if (!snapshot_valid)
        return snapshot_valid;
    if (identity.binary_id().empty() || identity.load_profile_hash().empty() ||
        image.format != identity.format() || image.architecture != identity.architecture() ||
        image.architecture_mode != identity.architecture_mode() || image.abi != identity.abi() ||
        image.endian != identity.endian() || image.image_base != identity.image_base() ||
        image.workspace_binary_id != identity.binary_id() ||
        image.provider_content_hash != identity.content_hash() ||
        snapshot.binary_id != identity.binary_id() ||
        snapshot.load_profile_hash != identity.load_profile_hash() ||
        !revision.binary_id.constant_time_equal(identity.binary_id()) ||
        !revision.load_profile_hash.constant_time_equal(identity.load_profile_hash()) ||
        revision.generation != snapshot.generation ||
        revision.analysis_revision != snapshot.analysis_revision ||
        revision.overlay_revision != snapshot.overlay_revision) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "Ghidra function database inputs do not share one workspace identity and revision",
            "ghidra.function_db.create"));
    }
    if (!snapshot.normalized_image ||
        snapshot.normalized_image->workspace_binary_id != image.workspace_binary_id ||
        snapshot.normalized_image->provider_content_hash != image.provider_content_hash ||
        snapshot.normalized_image->format != image.format ||
        snapshot.normalized_image->architecture != image.architecture ||
        snapshot.normalized_image->architecture_mode != image.architecture_mode ||
        snapshot.normalized_image->abi != image.abi ||
        snapshot.normalized_image->endian != image.endian ||
        snapshot.normalized_image->image_base != image.image_base ||
        snapshot.normalized_image->image_size != image.image_size) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "analysis snapshot normalized image does not match the Ghidra function database image",
            "ghidra.function_db.create"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_language(const workspace_image_t& image,
                                           const ghidra_language_spec_t& language,
                                           const cancellation_token_t& cancel) {
    auto expected = resolve_ghidra_language(image, cancel);
    if (!expected)
        return workspace_result_t<void>::failure(expected.error());
    if (expected.value().family != language.family ||
        expected.value().language_id != language.language_id ||
        expected.value().compiler_spec_id != language.compiler_spec_id ||
        expected.value().language_root != language.language_root) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "Ghidra function database language does not match the normalized image",
            "ghidra.function_db.create"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_limits(const ghidra_function_database_limits_t& limits) {
    if (limits.max_functions == 0 || limits.max_symbols == 0 || limits.max_types == 0 ||
        limits.max_source_mappings == 0 || limits.max_record_string_bytes == 0 ||
        limits.max_total_string_bytes == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "Ghidra function database limits are invalid", "ghidra.function_db.create"));
    }
    return workspace_result_t<void>::success();
}

bool address_metadata_matches(const address_t& lhs, const address_t& rhs) noexcept {
    return lhs.space == rhs.space && lhs.architecture == rhs.architecture &&
           lhs.mode == rhs.mode;
}

bool image_address_in_bounds(const workspace_image_t& image, const address_t& address,
                             bool permit_end) noexcept {
    if (address.architecture != image.architecture || address.mode != image.architecture_mode)
        return false;
    std::uint64_t rva = address.value;
    switch (address.space) {
    case address_space_id_t::relative_virtual:
        break;
    case address_space_id_t::virtual_address:
    case address_space_id_t::live_virtual:
        if (rva < image.image_base)
            return false;
        rva -= image.image_base;
        break;
    default:
        return false;
    }
    if (!workspace_image_span_within(rva, 0, image.image_size))
        return false;
    return permit_end || rva < image.image_size;
}

bool function_contains(const ghidra_function_record_t& function,
                       const address_t& address) noexcept {
    return address_metadata_matches(function.key.address, address) &&
           address.value >= function.key.address.value && address.value < function.end.value;
}

bool consume_string(const std::string& value,
                    const ghidra_function_database_limits_t& limits,
                    std::uint64_t& total) noexcept {
    const std::uint64_t size = static_cast<std::uint64_t>(value.size());
    if (size > limits.max_record_string_bytes || size > limits.max_total_string_bytes - total)
        return false;
    for (char value_char : value) {
        if (value_char == '\0')
            return false;
    }
    total += size;
    return true;
}

std::string make_ghidra_name(const std::string& name, entity_id_t id) {
    std::string output;
    output.reserve(name.size() + 32);
    for (char value : name) {
        const unsigned char character = static_cast<unsigned char>(value);
        output.push_back(std::isalnum(character) || value == '_' ? value : '_');
    }
    if (output.empty()) {
        char generated[32]{};
        std::snprintf(generated, sizeof(generated), "sym_%llu",
            static_cast<unsigned long long>(id));
        output.assign(generated);
    }
    if (std::isdigit(static_cast<unsigned char>(output.front())))
        output.insert(output.begin(), '_');
    return output;
}

bool function_order(const ghidra_function_record_t& lhs,
                    const ghidra_function_record_t& rhs) noexcept {
    if (lhs.key.address != rhs.key.address)
        return lhs.key.address < rhs.key.address;
    return lhs.key.entity_id < rhs.key.entity_id;
}

bool symbol_order(const ghidra_symbol_record_t& lhs,
                  const ghidra_symbol_record_t& rhs) noexcept {
    if (lhs.key.address != rhs.key.address)
        return lhs.key.address < rhs.key.address;
    return lhs.key.entity_id < rhs.key.entity_id;
}

bool type_order(const ghidra_type_record_t& lhs, const ghidra_type_record_t& rhs) noexcept {
    return lhs.id < rhs.id;
}

bool source_order(const ghidra_source_mapping_t& lhs,
                  const ghidra_source_mapping_t& rhs) noexcept {
    if (lhs.function_id != rhs.function_id)
        return lhs.function_id < rhs.function_id;
    if (lhs.address != rhs.address)
        return lhs.address < rhs.address;
    return lhs.id < rhs.id;
}

}

std::size_t ghidra_entity_address_key_hash_t::operator()(
    const ghidra_entity_address_key_t& key) const noexcept {
    std::size_t value = address_hash_t{}(key.address);
    const std::size_t entity = static_cast<std::size_t>(key.entity_id ^ (key.entity_id >> 33));
    value ^= entity + static_cast<std::size_t>(0x9e3779b9U) + (value << 6) + (value >> 2);
    return value;
}

ghidra_function_database_t::ghidra_function_database_t(
    ghidra_language_spec_t language,
    ghidra_adapter_revision_t revision,
    ghidra_adapter_cache_key_t cache_key,
    std::vector<ghidra_function_record_t> functions,
    std::vector<ghidra_symbol_record_t> symbols,
    std::vector<ghidra_type_record_t> types,
    std::vector<ghidra_source_mapping_t> source_mappings,
    std::unordered_map<entity_id_t, std::size_t> function_by_id,
    std::unordered_map<ghidra_entity_address_key_t, std::size_t,
                       ghidra_entity_address_key_hash_t> function_by_key,
    std::unordered_map<entity_id_t, std::size_t> symbol_by_id,
    std::unordered_map<ghidra_entity_address_key_t, std::size_t,
                       ghidra_entity_address_key_hash_t> symbol_by_key,
    std::unordered_map<entity_id_t, std::size_t> type_by_id)
    : language_(std::move(language)),
      revision_(std::move(revision)),
      cache_key_(std::move(cache_key)),
      functions_(std::move(functions)),
      symbols_(std::move(symbols)),
      types_(std::move(types)),
      source_mappings_(std::move(source_mappings)),
      function_by_id_(std::move(function_by_id)),
      function_by_key_(std::move(function_by_key)),
      symbol_by_id_(std::move(symbol_by_id)),
      symbol_by_key_(std::move(symbol_by_key)),
      type_by_id_(std::move(type_by_id)) {}

workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>
ghidra_function_database_t::create(
    const workspace_identity_t& identity,
    const workspace_image_t& image,
    const analysis_snapshot_t& snapshot,
    ghidra_language_spec_t language,
    ghidra_adapter_revision_t revision,
    std::vector<ghidra_type_record_t> types,
    std::vector<ghidra_source_mapping_t> source_mappings,
    ghidra_function_database_limits_t limits,
    const cancellation_token_t& cancel) {
    auto inputs_valid = validate_identity(identity, image, snapshot, revision, cancel);
    if (!inputs_valid)
        return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
            inputs_valid.error());
    auto language_valid = validate_language(image, language, cancel);
    if (!language_valid)
        return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
            language_valid.error());
    auto limits_valid = validate_limits(limits);
    if (!limits_valid)
        return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
            limits_valid.error());
    if (snapshot.functions.size() > limits.max_functions ||
        snapshot.symbols.size() > limits.max_symbols || types.size() > limits.max_types ||
        source_mappings.size() > limits.max_source_mappings) {
        return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "Ghidra function database records exceed their configured limits",
                "ghidra.function_db.create"));
    }
    auto cache_key = make_ghidra_adapter_cache_key(revision, language, cancel);
    if (!cache_key)
        return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
            cache_key.error());

    try {
        std::uint64_t string_bytes = 0;
        std::vector<ghidra_symbol_record_t> symbols;
        symbols.reserve(snapshot.symbols.size());
        for (const auto& source : snapshot.symbols) {
            auto stop = stopped(cancel, "ghidra.function_db.symbols");
            if (!stop)
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    stop.error());
            if (source.id == 0 || !image_address_in_bounds(image, source.address, false) ||
                !consume_string(source.name, limits, string_bytes)) {
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "analysis snapshot contains an invalid symbol for the Ghidra function database",
                        "ghidra.function_db.symbols"));
            }
            ghidra_symbol_record_t record;
            record.key = ghidra_entity_address_key_t{source.id, source.address};
            record.name = source.name;
            record.ghidra_name = make_ghidra_name(source.name, source.id);
            if (!consume_string(record.ghidra_name, limits, string_bytes)) {
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "Ghidra symbol name exceeds the function database string budget",
                        "ghidra.function_db.symbols"));
            }
            record.kind = source.kind;
            record.provenance = source.provenance;
            record.confidence = source.confidence;
            symbols.push_back(std::move(record));
        }
        std::sort(symbols.begin(), symbols.end(), symbol_order);
        std::unordered_map<entity_id_t, std::size_t> symbol_by_id;
        std::unordered_map<ghidra_entity_address_key_t, std::size_t,
                           ghidra_entity_address_key_hash_t> symbol_by_key;
        symbol_by_id.reserve(symbols.size());
        symbol_by_key.reserve(symbols.size());
        for (std::size_t index = 0; index < symbols.size(); ++index) {
            auto stop = stopped(cancel, "ghidra.function_db.symbols");
            if (!stop)
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    stop.error());
            if (!symbol_by_id.emplace(symbols[index].key.entity_id, index).second ||
                !symbol_by_key.emplace(symbols[index].key, index).second) {
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "analysis snapshot contains duplicate Ghidra symbol identity keys",
                        "ghidra.function_db.symbols"));
            }
        }

        std::vector<ghidra_function_record_t> functions;
        functions.reserve(snapshot.functions.size());
        for (const auto& source : snapshot.functions) {
            auto stop = stopped(cancel, "ghidra.function_db.functions");
            if (!stop)
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    stop.error());
            if (source.id == 0 || !address_metadata_matches(source.start, source.end) ||
                source.end.value <= source.start.value ||
                !image_address_in_bounds(image, source.start, false) ||
                !image_address_in_bounds(image, source.end, true)) {
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "analysis snapshot contains an invalid function range for Ghidra",
                        "ghidra.function_db.functions"));
            }
            for (const auto& chunk : source.chunks) {
                if (chunk.rva_start >= chunk.rva_end || chunk.rva_end > image.image_size) {
                    return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                        make_workspace_error(workspace_error_code_t::integrity_failure,
                            "analysis snapshot contains an invalid function chunk for Ghidra",
                            "ghidra.function_db.functions"));
                }
            }
            ghidra_function_record_t record;
            record.key = ghidra_entity_address_key_t{source.id, source.start};
            record.end = source.end;
            record.symbol_id = source.symbol_id;
            if (record.symbol_id) {
                if (*record.symbol_id == 0) {
                    return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                        make_workspace_error(workspace_error_code_t::integrity_failure,
                            "analysis snapshot function contains an invalid symbol identity",
                            "ghidra.function_db.functions"));
                }
                const auto symbol = symbol_by_id.find(*record.symbol_id);
                if (symbol == symbol_by_id.end()) {
                    return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                        make_workspace_error(workspace_error_code_t::integrity_failure,
                            "analysis snapshot function references a missing symbol identity",
                            "ghidra.function_db.functions"));
                }
                record.name = symbols[symbol->second].ghidra_name;
                record.display_name = symbols[symbol->second].name;
            } else {
                char generated[32]{};
                std::snprintf(generated, sizeof(generated), "sub_%llu",
                    static_cast<unsigned long long>(source.id));
                record.name.assign(generated);
                record.display_name = record.name;
            }
            if (!consume_string(record.name, limits, string_bytes) ||
                !consume_string(record.display_name, limits, string_bytes)) {
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "Ghidra function name exceeds the function database string budget",
                        "ghidra.function_db.functions"));
            }
            record.provenance = source.provenance;
            record.confidence = source.confidence;
            record.thunk = source.thunk;
            record.noreturn = source.noreturn;
            record.chunks = source.chunks;
            functions.push_back(std::move(record));
        }
        std::sort(functions.begin(), functions.end(), function_order);
        std::unordered_map<entity_id_t, std::size_t> function_by_id;
        std::unordered_map<ghidra_entity_address_key_t, std::size_t,
                           ghidra_entity_address_key_hash_t> function_by_key;
        function_by_id.reserve(functions.size());
        function_by_key.reserve(functions.size());
        for (std::size_t index = 0; index < functions.size(); ++index) {
            auto stop = stopped(cancel, "ghidra.function_db.functions");
            if (!stop)
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    stop.error());
            if (!function_by_id.emplace(functions[index].key.entity_id, index).second ||
                !function_by_key.emplace(functions[index].key, index).second) {
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "analysis snapshot contains duplicate Ghidra function identity keys",
                        "ghidra.function_db.functions"));
            }
        }

        for (auto& type : types) {
            auto stop = stopped(cancel, "ghidra.function_db.types");
            if (!stop)
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    stop.error());
            if (type.id == 0 || type.display_name.empty() || type.canonical_type.empty() ||
                (type.address && !image_address_in_bounds(image, *type.address, false)) ||
                !consume_string(type.display_name, limits, string_bytes) ||
                !consume_string(type.canonical_type, limits, string_bytes)) {
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "Ghidra function database type metadata is invalid",
                        "ghidra.function_db.types"));
            }
        }
        std::sort(types.begin(), types.end(), type_order);
        std::unordered_map<entity_id_t, std::size_t> type_by_id;
        type_by_id.reserve(types.size());
        for (std::size_t index = 0; index < types.size(); ++index) {
            auto stop = stopped(cancel, "ghidra.function_db.types");
            if (!stop)
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    stop.error());
            if (!type_by_id.emplace(types[index].id, index).second) {
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "Ghidra function database contains duplicate type identities",
                        "ghidra.function_db.types"));
            }
        }

        for (const auto& source : source_mappings) {
            auto stop = stopped(cancel, "ghidra.function_db.source_map");
            if (!stop)
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    stop.error());
            const auto function = function_by_id.find(source.function_id);
            if (source.id == 0 || source.function_id == 0 || source.source_line == 0 ||
                source.source_path.empty() || function == function_by_id.end() ||
                !function_contains(functions[function->second], source.address) ||
                !consume_string(source.source_path, limits, string_bytes)) {
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "Ghidra function database source mapping is invalid",
                        "ghidra.function_db.source_map"));
            }
        }
        std::sort(source_mappings.begin(), source_mappings.end(), source_order);
        std::unordered_set<entity_id_t> source_ids;
        source_ids.reserve(source_mappings.size());
        for (const auto& source : source_mappings) {
            auto stop = stopped(cancel, "ghidra.function_db.source_map");
            if (!stop)
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    stop.error());
            if (!source_ids.emplace(source.id).second) {
                return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "Ghidra function database contains duplicate source mapping identities",
                        "ghidra.function_db.source_map"));
            }
        }

        auto database = std::shared_ptr<const ghidra_function_database_t>(
            new ghidra_function_database_t(std::move(language), std::move(revision),
                cache_key.take_value(), std::move(functions), std::move(symbols),
                std::move(types), std::move(source_mappings), std::move(function_by_id),
                std::move(function_by_key), std::move(symbol_by_id), std::move(symbol_by_key),
                std::move(type_by_id)));
        return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::success(
            std::move(database));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const ghidra_function_database_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "Ghidra function database allocation exceeds its configured budget",
                "ghidra.function_db.create"));
    }
}

const ghidra_function_record_t* ghidra_function_database_t::find_function(
    const ghidra_entity_address_key_t& key) const noexcept {
    const auto found = function_by_key_.find(key);
    return found == function_by_key_.end() ? nullptr : &functions_[found->second];
}

const ghidra_function_record_t* ghidra_function_database_t::find_function(
    entity_id_t id) const noexcept {
    const auto found = function_by_id_.find(id);
    return found == function_by_id_.end() ? nullptr : &functions_[found->second];
}

const ghidra_function_record_t* ghidra_function_database_t::find_containing_function(
    const address_t& address) const noexcept {
    const ghidra_function_record_t* best = nullptr;
    for (const auto& function : functions_) {
        if (!function_contains(function, address))
            continue;
        const std::uint64_t size = function.end.value - function.key.address.value;
        if (!best || size < best->end.value - best->key.address.value ||
            (size == best->end.value - best->key.address.value &&
             function.key.entity_id < best->key.entity_id)) {
            best = &function;
        }
    }
    return best;
}

const ghidra_symbol_record_t* ghidra_function_database_t::find_symbol(
    const ghidra_entity_address_key_t& key) const noexcept {
    const auto found = symbol_by_key_.find(key);
    return found == symbol_by_key_.end() ? nullptr : &symbols_[found->second];
}

const ghidra_symbol_record_t* ghidra_function_database_t::find_symbol(
    entity_id_t id) const noexcept {
    const auto found = symbol_by_id_.find(id);
    return found == symbol_by_id_.end() ? nullptr : &symbols_[found->second];
}

const ghidra_type_record_t* ghidra_function_database_t::find_type(entity_id_t id) const noexcept {
    const auto found = type_by_id_.find(id);
    return found == type_by_id_.end() ? nullptr : &types_[found->second];
}

}

#endif
