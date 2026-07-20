#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4099 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "aida_code_xml_parse.hpp"

#include "funcdata.hh"
#include "xml.hh"
#include "varnode.hh"
#include "op.hh"
#include "type.hh"
#include "fspec.hh"
#include "prettyprint.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

namespace aida_ghidra {

namespace {

struct parse_context_t
{
	ghidra::Funcdata* func;
	std::map<uint64_t, ghidra::PcodeOp*> ops;
	std::map<uint64_t, ghidra::Varnode*> varnodes;
	std::map<uint64_t, ghidra::Symbol*> symbols;
	std::ostringstream& stream;
	annotated_code_t& result;
	std::size_t max_annotations;
	std::atomic<bool>* cancel;
	bool cancelled;

	parse_context_t(ghidra::Funcdata* f, std::ostringstream& s, annotated_code_t& r,
	                std::size_t max_annotations_value, std::atomic<bool>* cancel_ptr)
		: func(f), stream(s), result(r),
		  max_annotations(max_annotations_value),
		  cancel(cancel_ptr), cancelled(false)
	{
		for (auto it = func->beginOpAll(); it != func->endOpAll(); ++it)
			ops[static_cast<uint64_t>(it->first.getTime())] = it->second;
		for (auto it = func->beginLoc(); it != func->endLoc(); ++it)
			varnodes[(*it)->getCreateIndex()] = *it;

		ghidra::ScopeLocal* map_local = func->getScopeLocal();
		auto iter = map_local->begin();
		auto enditer = map_local->end();
		for (; iter != enditer; ++iter) {
			const ghidra::SymbolEntry* entry = *iter;
			ghidra::Symbol* sym = entry->getSymbol();
			symbols[sym->getId()] = sym;
		}
	}

	bool check_cancelled() {
		if (cancelled)
			return true;
		if (cancel && cancel->load(std::memory_order_acquire)) {
			cancelled = true;
			return true;
		}
		return false;
	}

	bool annotations_full() const {
		return result.annotations.size() >= max_annotations;
	}
};

const std::string* attr_optional(const ghidra::Element* el, const char* name)
{
	int n = el->getNumAttributes();
	for (int i = 0; i < n; ++i) {
		if (el->getAttributeName(i) == name)
			return &el->getAttributeValue(i);
	}
	return nullptr;
}

uint64_t attr_ull(const ghidra::Element* el, const char* name, uint64_t default_value)
{
	const std::string* v = attr_optional(el, name);
	if (!v)
		return default_value;
	try {
		return std::stoull(*v, nullptr, 0);
	} catch (...) {
		return default_value;
	}
}

int attr_int(const ghidra::Element* el, const char* name, int default_value)
{
	const std::string* v = attr_optional(el, name);
	if (!v)
		return default_value;
	try {
		return std::stoi(*v, nullptr, 0);
	} catch (...) {
		return default_value;
	}
}

size_t stream_pos(std::ostringstream& s)
{
	return static_cast<size_t>(s.tellp());
}

void annotate_op_ref(const ghidra::Element* node, parse_context_t& ctx, std::vector<code_annotation_t>& out)
{
	uint64_t opref = attr_ull(node, "opref", ULLONG_MAX);
	if (opref == ULLONG_MAX)
		return;
	auto it = ctx.ops.find(opref);
	if (it == ctx.ops.end())
		return;
	auto op = it->second;
	code_annotation_t a;
	a.kind = annotation_kind_t::offset;
	a.offset = op->getAddr().getOffset();
	out.push_back(a);
}

void annotate_function_name(const ghidra::Element* node, parse_context_t& ctx, std::vector<code_annotation_t>& out)
{
	const std::string& fn_name = node->getContent();
	const std::string* opref_attr = attr_optional(node, "opref");
	if (!opref_attr) {
		if (ctx.func->getName() == fn_name) {
			code_annotation_t a;
			a.kind = annotation_kind_t::function_name;
			a.name = ctx.func->getName();
			a.offset = ctx.func->getAddress().getOffset();
			out.push_back(a);

			code_annotation_t off;
			off.kind = annotation_kind_t::offset;
			off.offset = a.offset;
			out.push_back(off);
		}
		return;
	}

	uint64_t opref = ULLONG_MAX;
	try {
		opref = std::stoull(*opref_attr, nullptr, 0);
	} catch (...) {
		return;
	}
	if (opref == ULLONG_MAX)
		return;

	auto it = ctx.ops.find(opref);
	if (it == ctx.ops.end())
		return;
	ghidra::PcodeOp* op = it->second;
	ghidra::FuncCallSpecs* spec = ctx.func->getCallSpecs(op);
	if (!spec)
		return;
	code_annotation_t a;
	a.kind = annotation_kind_t::function_name;
	a.name = spec->getName();
	a.offset = spec->getEntryAddress().getOffset();
	out.push_back(a);
}

void annotate_comment_offset(const ghidra::Element* node, parse_context_t& , std::vector<code_annotation_t>& out)
{
	uint64_t off = attr_ull(node, "off", ULLONG_MAX);
	if (off == ULLONG_MAX)
		return;
	code_annotation_t a;
	a.kind = annotation_kind_t::offset;
	a.offset = off;
	out.push_back(a);
}

void annotate_color(const ghidra::Element* node, parse_context_t& , std::vector<code_annotation_t>& out)
{
	int color = attr_int(node, "color", -1);
	if (color < 0)
		return;
	annotation_kind_t kind = annotation_kind_t::none;
	switch (color) {
	case ghidra::EmitMarkup::syntax_highlight::keyword_color:
		kind = annotation_kind_t::syntax_keyword;
		break;
	case ghidra::EmitMarkup::syntax_highlight::comment_color:
		kind = annotation_kind_t::syntax_comment;
		break;
	case ghidra::EmitMarkup::syntax_highlight::type_color:
		kind = annotation_kind_t::syntax_type;
		break;
	case ghidra::EmitMarkup::syntax_highlight::funcname_color:
		kind = annotation_kind_t::syntax_funcname;
		break;
	case ghidra::EmitMarkup::syntax_highlight::var_color:
		kind = annotation_kind_t::syntax_var;
		break;
	case ghidra::EmitMarkup::syntax_highlight::const_color:
		kind = annotation_kind_t::syntax_const;
		break;
	case ghidra::EmitMarkup::syntax_highlight::param_color:
		kind = annotation_kind_t::syntax_param;
		break;
	case ghidra::EmitMarkup::syntax_highlight::global_color:
		kind = annotation_kind_t::syntax_global;
		break;
	case ghidra::EmitMarkup::syntax_highlight::special_color:
		kind = annotation_kind_t::syntax_special;
		break;
	default:
		return;
	}
	code_annotation_t a;
	a.kind = kind;
	out.push_back(a);
}

void annotate_local_variable(ghidra::Symbol* sym, std::vector<code_annotation_t>& out)
{
	if (!sym)
		return;
	code_annotation_t a;
	a.name = sym->getName();
	a.kind = sym->getCategory() == 0
		? annotation_kind_t::function_parameter
		: annotation_kind_t::local_variable;
	out.push_back(a);
}

void annotate_global_variable(ghidra::Varnode* vn, std::vector<code_annotation_t>& out)
{
	if (!vn)
		return;
	code_annotation_t a;
	a.kind = annotation_kind_t::global_variable;
	a.offset = vn->getOffset();
	out.push_back(a);
}

void annotate_constant_variable(ghidra::Varnode* vn, std::vector<code_annotation_t>& out)
{
	if (!vn)
		return;
	code_annotation_t a;
	a.kind = annotation_kind_t::constant_variable;
	a.offset = vn->getOffset();
	out.push_back(a);
}

void annotate_variable(const ghidra::Element* node, parse_context_t& ctx, std::vector<code_annotation_t>& out)
{
	const std::string* varref = attr_optional(node, "varref");
	if (!varref) {
		auto parent = node->getParent();
		if (parent && parent->getName() == "vardecl") {
			const std::string* symref = attr_optional(parent, "symref");
			if (!symref)
				return;
			uint64_t sym_id = 0;
			try { sym_id = std::stoull(*symref, nullptr, 0); } catch (...) { return; }
			auto sit = ctx.symbols.find(sym_id);
			if (sit == ctx.symbols.end())
				return;
			annotate_local_variable(sit->second, out);
		}
		return;
	}
	uint64_t vid = ULLONG_MAX;
	try { vid = std::stoull(*varref, nullptr, 0); } catch (...) { return; }
	if (vid == ULLONG_MAX)
		return;
	auto vit = ctx.varnodes.find(vid);
	if (vit == ctx.varnodes.end())
		return;
	auto vn = vit->second;
	ghidra::HighVariable* high = nullptr;
	try {
		high = vn->getHigh();
	} catch (const ghidra::LowlevelError&) {
		return;
	}
	if (!high)
		return;

	if (high->isPersist() && high->isAddrTied())
		annotate_global_variable(vn, out);
	else if (high->isConstant() && high->getType()->getMetatype() == ghidra::TYPE_PTR)
		annotate_constant_variable(vn, out);
	else if (!high->isPersist())
		annotate_local_variable(high->getSymbol(), out);
}

bool name_matches(const ghidra::Element* node, const char* name)
{
	const std::string& n = node->getName();
	return std::strcmp(n.c_str(), name) == 0;
}

void parse_node_(const ghidra::Element* node, parse_context_t& ctx)
{
	if (!node)
		return;
	if (ctx.check_cancelled())
		return;
	if (ctx.annotations_full())
		return;

	const std::string& name = node->getName();
	std::vector<code_annotation_t> annotations;

	if (name == "break") {
		ctx.stream << "\n";
		int indent = attr_int(node, "indent", 0);
		for (int i = 0; i < indent; ++i)
			ctx.stream << ' ';
	} else {
		if (name == "statement") {
			annotate_op_ref(node, ctx, annotations);
		} else if (name == "op") {
			annotate_op_ref(node, ctx, annotations);
			annotate_color(node, ctx, annotations);
		} else if (name == "comment") {
			annotate_comment_offset(node, ctx, annotations);
			annotate_color(node, ctx, annotations);
		} else if (name == "variable") {
			annotate_variable(node, ctx, annotations);
			annotate_color(node, ctx, annotations);
		} else if (name == "funcname") {
			annotate_function_name(node, ctx, annotations);
			annotate_color(node, ctx, annotations);
		} else if (name == "type" || name == "syntax" || name == "value") {
			annotate_color(node, ctx, annotations);
		}

		size_t start_pos = stream_pos(ctx.stream);
		for (auto& a : annotations)
			a.start = start_pos;
	}

	const std::string& content = node->getContent();
	if (!content.empty())
		ctx.stream << content;

	const ghidra::List& children = node->getChildren();
	for (auto* child : children) {
		if (ctx.check_cancelled() || ctx.annotations_full())
			break;
		parse_node_(child, ctx);
	}

	for (auto& a : annotations) {
		a.end = stream_pos(ctx.stream);
		ctx.result.annotations.push_back(std::move(a));
	}
}

void compute_line_to_address_(annotated_code_t& code, std::size_t max_line_mappings,
                              std::atomic<bool>* cancel)
{
	std::map<int, uint64_t> line_to_addr;
	int line = 0;
	size_t pos = 0;
	std::map<size_t, uint64_t> annotation_byte_to_addr;
	for (auto& a : code.annotations) {
		if (a.kind != annotation_kind_t::offset)
			continue;
		annotation_byte_to_addr[a.start] = a.offset;
	}
	auto annot_it = annotation_byte_to_addr.begin();
	for (size_t i = 0; i < code.code.size(); ++i) {
		if (cancel && cancel->load(std::memory_order_acquire))
			break;
		while (annot_it != annotation_byte_to_addr.end() && annot_it->first <= i) {
			if (line_to_addr.find(line) == line_to_addr.end())
				line_to_addr[line] = annot_it->second;
			++annot_it;
		}
		if (code.code[i] == '\n') {
			line++;
		}
		(void)pos;
	}
	code.line_to_address.reserve(std::min(line_to_addr.size(), max_line_mappings));
	for (auto& kv : line_to_addr) {
		if (code.line_to_address.size() >= max_line_mappings)
			break;
		code.line_to_address.emplace_back(kv.first, kv.second);
	}
}

}

bool parse_code_xml(ghidra::Funcdata* func, const std::string& xml, annotated_code_t& out,
                    std::size_t max_annotations, std::size_t max_line_mappings,
                    std::atomic<bool>* cancel)
{
	out.code.clear();
	out.annotations.clear();
	out.line_to_address.clear();

	if (!func || xml.empty())
		return false;

	if (cancel && cancel->load(std::memory_order_acquire))
		return false;

	std::istringstream iss(xml);
	ghidra::Document* doc = nullptr;
	try {
		doc = ghidra::xml_tree(iss);
	} catch (const ghidra::DecoderError&) {
		return false;
	} catch (const ghidra::LowlevelError&) {
		return false;
	} catch (...) {
		return false;
	}
	if (!doc)
		return false;

	out.annotations.reserve(std::min<std::size_t>(
		xml.size() / 16, max_annotations));

	std::ostringstream stream;
	parse_context_t ctx(func, stream, out, max_annotations, cancel);

	const ghidra::Element* root = doc->getRoot();
	if (root) {
		parse_node_(root, ctx);
	}

	out.code = stream.str();
	delete doc;

	if (cancel && cancel->load(std::memory_order_acquire))
		return false;

	compute_line_to_address_(out, max_line_mappings, cancel);
	return true;
}

}
