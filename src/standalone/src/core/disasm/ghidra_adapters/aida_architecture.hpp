#pragma once

#include "aida_ghidra_preamble.hpp"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "architecture.hh"
#include "sleigh_arch.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "aida_function_db.hpp"

struct DisasmFile;

namespace aida_ghidra {

class load_image_t;

class architecture_t : public ghidra::SleighArchitecture
{
private:
	std::map<std::string, ghidra::VarnodeData> registers_;
	std::vector<std::string> warnings_;
	function_db_t symbol_db_;
	bool rawptr_ = true;
	bool owns_loader_ = false;

	void load_registers_(const ghidra::Translate* translate);

public:
	architecture_t(const std::string& target,
	               std::ostream* err_stream);

	void take_loader(std::unique_ptr<load_image_t> loader);

	function_db_t& symbol_database() { return symbol_db_; }
	const function_db_t& symbol_database() const { return symbol_db_; }

	void apply_pdb_types();
	void apply_pdb_function_prototypes();

	static std::string current_apply_pdb_name();
	static const char* current_apply_pdb_stage();

	ghidra::ProtoModel* proto_model_from_cc(const std::string& cc) const;
	ghidra::Address register_address_from_name(const std::string& reg_name) const;

	void add_warning(const std::string& warning) { warnings_.push_back(warning); }
	const std::vector<std::string>& warnings() const { return warnings_; }

	ghidra::ContextDatabase* context_database() { return context; }

	void set_rawptr(bool v) { rawptr_ = v; }
	bool rawptr() const { return rawptr_; }

protected:
	ghidra::Translate* buildTranslator(ghidra::DocumentStorage& store) override;
	void buildLoader(ghidra::DocumentStorage& store) override;
	ghidra::Scope* buildDatabase(ghidra::DocumentStorage& store) override;
	void buildTypegrp(ghidra::DocumentStorage& store) override;
	void buildCoreTypes(ghidra::DocumentStorage& store) override;
	void buildCommentDB(ghidra::DocumentStorage& store) override;
	void postSpecFile() override;
	void buildAction(ghidra::DocumentStorage& store) override;

private:
	std::unique_ptr<load_image_t> staged_loader_;
};

}
