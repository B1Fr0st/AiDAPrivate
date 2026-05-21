#pragma once

#include "aida_ghidra_preamble.hpp"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "comment.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

namespace aida_ghidra {

class comment_database_t : public ghidra::CommentDatabase
{
public:
	comment_database_t() = default;

	void clear() override { cache_.clear(); }
	void clearType(const ghidra::Address& fad, ghidra::uint4 tp) override { cache_.clearType(fad, tp); }

	void addComment(ghidra::uint4 tp,
	                const ghidra::Address& fad,
	                const ghidra::Address& ad,
	                const std::string& txt) override
	{
		cache_.addComment(tp, fad, ad, txt);
	}

	bool addCommentNoDuplicate(ghidra::uint4 tp,
	                           const ghidra::Address& fad,
	                           const ghidra::Address& ad,
	                           const std::string& txt) override
	{
		return cache_.addCommentNoDuplicate(tp, fad, ad, txt);
	}

	void deleteComment(ghidra::Comment* ) override
	{
		throw ghidra::LowlevelError("comment_database_t::deleteComment not supported");
	}

	ghidra::CommentSet::const_iterator beginComment(const ghidra::Address& fad) const override
	{
		return cache_.beginComment(fad);
	}

	ghidra::CommentSet::const_iterator endComment(const ghidra::Address& fad) const override
	{
		return cache_.endComment(fad);
	}

	void encode(ghidra::Encoder& encoder) const override { cache_.encode(encoder); }
	void decode(ghidra::Decoder& ) override
	{
		throw ghidra::LowlevelError("comment_database_t::decode not supported");
	}

private:
	mutable ghidra::CommentDatabaseInternal cache_;
};

}
