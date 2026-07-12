#include "regex_query.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <string>
#include <utility>

#ifndef PCRE2_CODE_UNIT_WIDTH
#define PCRE2_CODE_UNIT_WIDTH 8
#endif
#ifndef PCRE2_STATIC
#define PCRE2_STATIC
#endif
#if __has_include(<pcre2.h>)
#include <pcre2.h>
#elif __has_include("../../../../../../.deps/pcre2-10.47/src/pcre2.h.generic")
#include "../../../../../../.deps/pcre2-10.47/src/pcre2.h.generic"
#else
#error PCRE2 10.47 headers are required for bounded regex queries
#endif

namespace aida::analysis {
namespace {

constexpr std::uint32_t kMaximumPatternBytes = 16U * 1024U * 1024U;
constexpr std::uint32_t kMaximumSubjectBytes = 64U * 1024U * 1024U;
constexpr std::uint32_t kMaximumCompiledBytes = 64U * 1024U * 1024U;
constexpr std::uint32_t kMaximumCaptureCount = 4096;
constexpr std::uint32_t kMaximumParenthesisDepth = 1000;
constexpr std::uint32_t kMaximumVariableLookbehind = 65535;
constexpr std::uint32_t kMaximumMatchLimit = 1000000000U;
constexpr std::uint32_t kMaximumDepthLimit = 1000000U;
constexpr std::uint32_t kMaximumHeapLimitKib = 1024U * 1024U;
constexpr std::uint64_t kMaximumElapsedNs = 10ULL * 1000ULL * 1000ULL * 1000ULL;

std::string pcre2_error_message(int code) {
    std::array<PCRE2_UCHAR, 256> buffer{};
    const int length = pcre2_get_error_message(code, buffer.data(), buffer.size());
    if (length <= 0)
        return "PCRE2 error " + std::to_string(code);
    return std::string(reinterpret_cast<const char*>(buffer.data()),
        static_cast<std::size_t>(length));
}

workspace_error_t cancellation_error(const cancellation_token_t& cancel,
    bool query_deadline) {
    if (query_deadline || cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "bounded regular-expression query exceeded its deadline", "regex_query");
        error.cancellation = cancel.stop_requested();
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "bounded regular-expression query was cancelled", "regex_query");
    error.cancellation = true;
    return error;
}

workspace_result_t<void> validate_regex_limits_impl(const regex_query_limits_t& limits) {
    if (limits.max_pattern_bytes == 0 || limits.max_pattern_bytes > kMaximumPatternBytes ||
        limits.max_subject_bytes == 0 || limits.max_subject_bytes > kMaximumSubjectBytes ||
        limits.max_compiled_bytes == 0 || limits.max_compiled_bytes > kMaximumCompiledBytes ||
        limits.max_capture_count > kMaximumCaptureCount ||
        limits.max_parenthesis_depth == 0 ||
        limits.max_parenthesis_depth > kMaximumParenthesisDepth ||
        limits.max_variable_lookbehind > kMaximumVariableLookbehind ||
        limits.match_limit == 0 || limits.match_limit > kMaximumMatchLimit ||
        limits.depth_limit == 0 || limits.depth_limit > kMaximumDepthLimit ||
        limits.heap_limit_kib == 0 || limits.heap_limit_kib > kMaximumHeapLimitKib ||
        limits.max_elapsed_ns == 0 || limits.max_elapsed_ns > kMaximumElapsedNs) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "regular-expression resource limits are invalid", "regex_query"));
    }
    return workspace_result_t<void>::success();
}

bool invalid_utf_error(int code) noexcept {
    return (code <= PCRE2_ERROR_UTF8_ERR1 && code >= PCRE2_ERROR_UTF8_ERR21) ||
        code == PCRE2_ERROR_BADUTFOFFSET;
}

struct callout_state_t {
    cancellation_token_t cancel;
    std::chrono::steady_clock::time_point deadline;
    std::uint64_t steps = 0;
    bool cancellation_observed = false;
    bool deadline_observed = false;
};

int regex_callout(pcre2_callout_block*, void* data) noexcept {
    auto* state = static_cast<callout_state_t*>(data);
    if (!state)
        return PCRE2_ERROR_CALLOUT;
    if (state->steps != std::numeric_limits<std::uint64_t>::max())
        ++state->steps;
    if ((state->steps & 0x3fULL) != 1ULL)
        return 0;
    if (state->cancel.stop_requested()) {
        state->cancellation_observed = true;
        state->deadline_observed = state->cancel.deadline_exceeded();
        return PCRE2_ERROR_CALLOUT;
    }
    if (std::chrono::steady_clock::now() >= state->deadline) {
        state->deadline_observed = true;
        return PCRE2_ERROR_CALLOUT;
    }
    return 0;
}

}

struct regex_query_t::impl_t {
    std::string pattern;
    regex_compile_options_t options;
    regex_query_limits_t limits;
    pcre2_code* code = nullptr;
    std::uint32_t capture_count = 0;
    std::uint64_t compiled_bytes = 0;

    ~impl_t() {
        if (code)
            pcre2_code_free(code);
    }
};

struct regex_match_session_t::impl_t {
    std::shared_ptr<const regex_query_t> owner;
    const pcre2_code* code = nullptr;
    regex_query_limits_t limits;
    pcre2_match_context* context = nullptr;
    pcre2_match_data* data = nullptr;
    callout_state_t callout;
    std::uint64_t subjects = 0;

    ~impl_t() {
        if (data)
            pcre2_match_data_free(data);
        if (context)
            pcre2_match_context_free(context);
    }
};

regex_match_session_t::regex_match_session_t(std::unique_ptr<impl_t> impl) noexcept
    : impl_(std::move(impl)) {}

regex_match_session_t::regex_match_session_t(regex_match_session_t&&) noexcept = default;
regex_match_session_t& regex_match_session_t::operator=(regex_match_session_t&&) noexcept = default;
regex_match_session_t::~regex_match_session_t() = default;

workspace_result_t<regex_match_result_t> regex_match_session_t::match(
    std::string_view subject) {
    if (!impl_ || !impl_->owner || !impl_->code || !impl_->context || !impl_->data) {
        return workspace_result_t<regex_match_result_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "regular-expression match session is incomplete", "regex_query"));
    }
    if (subject.size() > impl_->limits.max_subject_bytes) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
            "regular-expression subject exceeds its byte limit", "regex_query");
        error.size = subject.size();
        error.details.emplace_back("maximum",
            std::to_string(impl_->limits.max_subject_bytes));
        return workspace_result_t<regex_match_result_t>::failure(std::move(error));
    }
    if (impl_->callout.cancel.stop_requested()) {
        return workspace_result_t<regex_match_result_t>::failure(
            cancellation_error(impl_->callout.cancel, false));
    }
    if (std::chrono::steady_clock::now() >= impl_->callout.deadline) {
        return workspace_result_t<regex_match_result_t>::failure(
            cancellation_error(impl_->callout.cancel, true));
    }
    if (impl_->subjects != std::numeric_limits<std::uint64_t>::max())
        ++impl_->subjects;
    impl_->callout.cancellation_observed = false;
    impl_->callout.deadline_observed = false;
    const auto initial_steps = impl_->callout.steps;
    static constexpr PCRE2_UCHAR empty_subject = 0;
    const auto* subject_data = subject.empty()
        ? &empty_subject : reinterpret_cast<PCRE2_SPTR>(subject.data());
    const int result = pcre2_match(impl_->code,
        subject_data, subject.size(), 0, 0,
        impl_->data, impl_->context);
    const auto consumed_steps = impl_->callout.steps - initial_steps;
    if (result == PCRE2_ERROR_NOMATCH) {
        regex_match_result_t match;
        match.engine_steps = consumed_steps;
        return workspace_result_t<regex_match_result_t>::success(match);
    }
    if (result >= 0) {
        const auto* offsets = pcre2_get_ovector_pointer(impl_->data);
        if (!offsets || offsets[0] == PCRE2_UNSET || offsets[1] == PCRE2_UNSET ||
            offsets[1] < offsets[0] || offsets[1] > subject.size()) {
            return workspace_result_t<regex_match_result_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "PCRE2 returned an invalid match range", "regex_query"));
        }
        regex_match_result_t match;
        match.matched = true;
        match.start = static_cast<std::size_t>(offsets[0]);
        match.length = static_cast<std::size_t>(offsets[1] - offsets[0]);
        match.engine_steps = consumed_steps;
        return workspace_result_t<regex_match_result_t>::success(match);
    }
    if (result == PCRE2_ERROR_CALLOUT &&
        (impl_->callout.cancellation_observed || impl_->callout.deadline_observed)) {
        return workspace_result_t<regex_match_result_t>::failure(
            cancellation_error(impl_->callout.cancel, impl_->callout.deadline_observed));
    }
    if (result == PCRE2_ERROR_MATCHLIMIT || result == PCRE2_ERROR_DEPTHLIMIT ||
        result == PCRE2_ERROR_HEAPLIMIT || result == PCRE2_ERROR_NOMEMORY) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
            "regular-expression engine resource limit was reached", "regex_query");
        error.provider_status = result;
        error.details.emplace_back("engine_error", pcre2_error_message(result));
        return workspace_result_t<regex_match_result_t>::failure(std::move(error));
    }
    if (invalid_utf_error(result)) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
            "regular-expression subject is not valid UTF-8", "regex_query");
        error.provider_status = result;
        error.details.emplace_back("engine_error", pcre2_error_message(result));
        return workspace_result_t<regex_match_result_t>::failure(std::move(error));
    }
    auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
        "PCRE2 matching failed", "regex_query");
    error.provider_status = result;
    error.details.emplace_back("engine_error", pcre2_error_message(result));
    return workspace_result_t<regex_match_result_t>::failure(std::move(error));
}

std::uint64_t regex_match_session_t::subjects_examined() const noexcept {
    return impl_ ? impl_->subjects : 0;
}

std::uint64_t regex_match_session_t::engine_steps() const noexcept {
    return impl_ ? impl_->callout.steps : 0;
}

regex_query_t::regex_query_t(std::unique_ptr<impl_t> impl) noexcept
    : impl_(std::move(impl)) {}

regex_query_t::~regex_query_t() = default;

workspace_result_t<std::shared_ptr<const regex_query_t>> regex_query_t::compile(
    std::string_view pattern, const regex_compile_options_t& options,
    const regex_query_limits_t& limits) {
    try {
        auto valid = validate_regex_limits_impl(limits);
        if (!valid)
            return workspace_result_t<std::shared_ptr<const regex_query_t>>::failure(valid.error());
        if (pattern.empty() || pattern.size() > limits.max_pattern_bytes) {
            auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                "regular-expression pattern is outside the allowed byte range", "regex_query");
            error.size = pattern.size();
            error.details.emplace_back("maximum", std::to_string(limits.max_pattern_bytes));
            return workspace_result_t<std::shared_ptr<const regex_query_t>>::failure(
                std::move(error));
        }
        if (options.literal && (options.multiline || options.dot_all || options.extended)) {
            return workspace_result_t<std::shared_ptr<const regex_query_t>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "literal regular-expression mode has incompatible options",
                    "regex_query"));
        }
        pcre2_compile_context* compile_context = pcre2_compile_context_create(nullptr);
        if (!compile_context) {
            return workspace_result_t<std::shared_ptr<const regex_query_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "PCRE2 compile-context allocation failed", "regex_query"));
        }
        struct context_guard_t {
            pcre2_compile_context* value;
            ~context_guard_t() { pcre2_compile_context_free(value); }
        } context_guard{compile_context};
        if (pcre2_set_max_pattern_length(compile_context, limits.max_pattern_bytes) != 0 ||
            pcre2_set_parens_nest_limit(compile_context, limits.max_parenthesis_depth) != 0 ||
            pcre2_set_max_varlookbehind(compile_context,
                limits.max_variable_lookbehind) != 0) {
            return workspace_result_t<std::shared_ptr<const regex_query_t>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "PCRE2 rejected regular-expression compile limits", "regex_query"));
        }
        std::uint32_t compile_options = PCRE2_UTF | PCRE2_AUTO_CALLOUT |
            PCRE2_NO_START_OPTIMIZE;
        if (options.literal)
            compile_options |= PCRE2_LITERAL;
        else
            compile_options |= PCRE2_UCP | PCRE2_NEVER_BACKSLASH_C;
        if (!options.case_sensitive)
            compile_options |= PCRE2_CASELESS;
        if (options.multiline)
            compile_options |= PCRE2_MULTILINE;
        if (options.dot_all)
            compile_options |= PCRE2_DOTALL;
        if (options.extended)
            compile_options |= PCRE2_EXTENDED;

        int error_code = 0;
        PCRE2_SIZE error_offset = 0;
        pcre2_code* code = pcre2_compile(
            reinterpret_cast<PCRE2_SPTR>(pattern.data()), pattern.size(), compile_options,
            &error_code, &error_offset, compile_context);
        if (!code) {
            auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                "regular-expression pattern did not compile", "regex_query");
            error.offset = static_cast<std::uint64_t>(error_offset);
            error.provider_status = error_code;
            error.details.emplace_back("engine_error", pcre2_error_message(error_code));
            return workspace_result_t<std::shared_ptr<const regex_query_t>>::failure(
                std::move(error));
        }
        struct code_guard_t {
            pcre2_code* value;
            ~code_guard_t() { if (value) pcre2_code_free(value); }
        } code_guard{code};
        std::uint32_t capture_count = 0;
        PCRE2_SIZE compiled_size = 0;
        const int capture_result = pcre2_pattern_info(code, PCRE2_INFO_CAPTURECOUNT,
            &capture_count);
        const int size_result = pcre2_pattern_info(code, PCRE2_INFO_SIZE, &compiled_size);
        if (capture_result != 0 || size_result != 0) {
            return workspace_result_t<std::shared_ptr<const regex_query_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "PCRE2 compiled-pattern metadata is unavailable", "regex_query"));
        }
        if (capture_count > limits.max_capture_count ||
            compiled_size > limits.max_compiled_bytes) {
            auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                "compiled regular expression exceeds structural limits", "regex_query");
            error.details.emplace_back("capture_count", std::to_string(capture_count));
            error.details.emplace_back("compiled_bytes", std::to_string(compiled_size));
            return workspace_result_t<std::shared_ptr<const regex_query_t>>::failure(
                std::move(error));
        }
        auto impl = std::make_unique<impl_t>();
        impl->pattern.assign(pattern.data(), pattern.size());
        impl->options = options;
        impl->limits = limits;
        impl->code = code;
        impl->capture_count = capture_count;
        impl->compiled_bytes = compiled_size;
        code_guard.value = nullptr;
        return workspace_result_t<std::shared_ptr<const regex_query_t>>::success(
            std::shared_ptr<const regex_query_t>(new regex_query_t(std::move(impl))));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const regex_query_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "regular-expression allocation exceeded available memory", "regex_query"));
    } catch (const std::length_error&) {
        return workspace_result_t<std::shared_ptr<const regex_query_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "regular-expression allocation exceeds container limits", "regex_query"));
    }
}

workspace_result_t<void> regex_query_t::validate_limits(
    const regex_query_limits_t& limits) {
    return validate_regex_limits_impl(limits);
}

std::string_view regex_query_t::pattern() const noexcept {
    return impl_->pattern;
}

const regex_compile_options_t& regex_query_t::options() const noexcept {
    return impl_->options;
}

const regex_query_limits_t& regex_query_t::limits() const noexcept {
    return impl_->limits;
}

std::uint32_t regex_query_t::capture_count() const noexcept {
    return impl_->capture_count;
}

std::uint64_t regex_query_t::compiled_bytes() const noexcept {
    return impl_->compiled_bytes;
}

workspace_result_t<regex_match_session_t> regex_query_t::create_session(
    const cancellation_token_t& cancel,
    std::optional<std::chrono::steady_clock::time_point> deadline) const {
    try {
        if (cancel.stop_requested())
            return workspace_result_t<regex_match_session_t>::failure(
                cancellation_error(cancel, false));
        const auto now = std::chrono::steady_clock::now();
        auto effective_deadline = now + std::chrono::nanoseconds(impl_->limits.max_elapsed_ns);
        if (deadline && *deadline < effective_deadline)
            effective_deadline = *deadline;
        const auto cancellation_deadline = cancel.deadline();
        if (cancellation_deadline && *cancellation_deadline < effective_deadline)
            effective_deadline = *cancellation_deadline;
        if (effective_deadline <= now)
            return workspace_result_t<regex_match_session_t>::failure(
                cancellation_error(cancel, true));

        auto session = std::make_unique<regex_match_session_t::impl_t>();
        session->owner = shared_from_this();
        session->code = impl_->code;
        session->limits = impl_->limits;
        session->callout.cancel = cancel;
        session->callout.deadline = effective_deadline;
        session->context = pcre2_match_context_create(nullptr);
        if (!session->context) {
            return workspace_result_t<regex_match_session_t>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "PCRE2 match-context allocation failed", "regex_query"));
        }
        session->data = pcre2_match_data_create_from_pattern(impl_->code, nullptr);
        if (!session->data) {
            return workspace_result_t<regex_match_session_t>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "PCRE2 match-data allocation failed", "regex_query"));
        }
        if (pcre2_set_match_limit(session->context, impl_->limits.match_limit) != 0 ||
            pcre2_set_depth_limit(session->context, impl_->limits.depth_limit) != 0 ||
            pcre2_set_heap_limit(session->context, impl_->limits.heap_limit_kib) != 0 ||
            pcre2_set_callout(session->context, regex_callout, &session->callout) != 0) {
            return workspace_result_t<regex_match_session_t>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "PCRE2 rejected regular-expression match limits", "regex_query"));
        }
        return workspace_result_t<regex_match_session_t>::success(
            regex_match_session_t(std::move(session)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<regex_match_session_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "regular-expression session allocation failed", "regex_query"));
    } catch (const std::bad_weak_ptr&) {
        return workspace_result_t<regex_match_session_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "regular-expression ownership is not immutable", "regex_query"));
    }
}

workspace_result_t<regex_match_result_t> regex_query_t::match(
    std::string_view subject, const cancellation_token_t& cancel,
    std::optional<std::chrono::steady_clock::time_point> deadline) const {
    auto session = create_session(cancel, deadline);
    if (!session)
        return workspace_result_t<regex_match_result_t>::failure(session.error());
    return session.value().match(subject);
}

}
