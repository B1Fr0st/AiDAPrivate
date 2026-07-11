#include "schema_validator.hpp"
#include "ida_compat_schemas.hpp"

#include <nlohmann/json-schema.hpp>

#include <algorithm>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace mcp_standalone::ida_compat
{
    namespace
    {
        validation_result_t make_failure(
            std::string path,
            std::string message,
            std::string schema_fragment = {})
        {
            validation_result_t result;
            result.valid = false;
            result.errors.push_back({
                std::move(path),
                std::move(message),
                std::move(schema_fragment)
            });
            return result;
        }

        std::string bounded_instance_fragment(const json& instance)
        {
            constexpr std::size_t max_fragment_length = 256;
            if (instance.is_array())
                return "array(size=" + std::to_string(instance.size()) + ")";
            if (instance.is_object())
                return "object(size=" + std::to_string(instance.size()) + ")";

            std::string fragment = instance.dump();
            if (fragment.size() > max_fragment_length)
                fragment.resize(max_fragment_length - 3), fragment += "...";
            return fragment;
        }

        void normalize_errors(std::vector<schema_error_t>& errors)
        {
            std::sort(errors.begin(), errors.end(), [](const schema_error_t& left, const schema_error_t& right) {
                if (left.path != right.path)
                    return left.path < right.path;
                if (left.message != right.message)
                    return left.message < right.message;
                return left.schema_fragment < right.schema_fragment;
            });
            errors.erase(std::unique(errors.begin(), errors.end(), [](const schema_error_t& left, const schema_error_t& right) {
                return left.path == right.path &&
                       left.message == right.message &&
                       left.schema_fragment == right.schema_fragment;
            }), errors.end());
        }

        std::string escape_json_pointer_token(const std::string& token)
        {
            std::string escaped;
            escaped.reserve(token.size());
            for (const char character : token) {
                if (character == '~')
                    escaped += "~0";
                else if (character == '/')
                    escaped += "~1";
                else
                    escaped += character;
            }
            return escaped;
        }

        bool find_external_reference(
            const json& value,
            const std::string& pointer,
            schema_error_t& error)
        {
            if (value.is_object()) {
                for (auto it = value.begin(); it != value.end(); ++it) {
                    const std::string child_pointer = pointer + "/" + escape_json_pointer_token(it.key());
                    if (it.key() == "$ref" || it.key() == "$recursiveRef" || it.key() == "$dynamicRef") {
                        if (!it.value().is_string() || it.value().get<std::string>().empty() ||
                            it.value().get<std::string>().front() != '#') {
                            error = {
                                child_pointer,
                                "external schema references are disabled",
                                it.value().is_string() ? it.value().get<std::string>() : "non-string reference"
                            };
                            return true;
                        }
                    }
                    if (find_external_reference(it.value(), child_pointer, error))
                        return true;
                }
            } else if (value.is_array()) {
                for (std::size_t index = 0; index < value.size(); ++index) {
                    if (find_external_reference(value[index], pointer + "/" + std::to_string(index), error))
                        return true;
                }
            }
            return false;
        }

        nlohmann::json_schema::schema_loader disabled_schema_loader()
        {
            return [](const nlohmann::json_uri&, json&) {
                throw std::runtime_error("external schema retrieval is disabled");
            };
        }

        class collecting_error_handler final : public nlohmann::json_schema::basic_error_handler
        {
        public:
            std::vector<schema_error_t> collected;

            void error(const json::json_pointer& pointer,
                       const json& instance,
                       const std::string& message) override
            {
                schema_error_t error;
                error.path = pointer.to_string();
                if (error.path.empty())
                    error.path = "(root)";
                error.message = message;
                error.schema_fragment = bounded_instance_fragment(instance);
                collected.push_back(std::move(error));
            }

            void reset() override
            {
                basic_error_handler::reset();
                collected.clear();
            }
        };

        validation_result_t validate_with_validator(
            nlohmann::json_schema::json_validator& validator,
            const json& args)
        {
            collecting_error_handler error_handler;
            try {
                validator.validate(args, error_handler, nlohmann::json_uri("#"));
            } catch (...) {
                return make_failure("(root)", "schema validation execution failed");
            }

            if (error_handler.collected.empty())
                return {};

            validation_result_t result;
            result.valid = false;
            result.errors = std::move(error_handler.collected);
            normalize_errors(result.errors);
            return result;
        }

        validation_result_t validate_with_schema(const json& args, const json& schema)
        {
            if (!schema.is_object())
                return make_failure("(schema)", "schema must be a JSON object");

            schema_error_t reference_error;
            if (find_external_reference(schema, "#", reference_error))
                return make_failure(
                    std::move(reference_error.path),
                    std::move(reference_error.message),
                    std::move(reference_error.schema_fragment));

            try {
                nlohmann::json_schema::json_validator validator(disabled_schema_loader(), nullptr, nullptr);
                validator.set_root_schema(schema);
                return validate_with_validator(validator, args);
            } catch (...) {
                return make_failure("(schema)", "schema validator setup failed");
            }
        }

        class schema_validator_registry final
        {
        public:
            static schema_validator_registry& instance()
            {
                static schema_validator_registry registry;
                return registry;
            }

            void register_schemas()
            {
                std::call_once(initialization_once_, [this]() {
                    initialize();
                });
            }

            validation_result_t status()
            {
                register_schemas();
                if (setup_error_.message.empty())
                    return {};
                return make_failure(
                    setup_error_.path,
                    setup_error_.message,
                    setup_error_.schema_fragment);
            }

            validation_result_t validate(const std::string& tool_name, const json& args)
            {
                register_schemas();
                if (!setup_error_.message.empty())
                    return make_failure(
                        setup_error_.path,
                        setup_error_.message,
                        setup_error_.schema_fragment);

                const auto validator = validators_.find(tool_name);
                if (validator == validators_.end())
                    return make_failure("(tool)", "unknown IDA-compatible MCP tool", tool_name);

                if (!args.is_object())
                    return make_failure("(root)", "arguments must be a JSON object", bounded_instance_fragment(args));

                return validate_with_validator(*validator->second, args);
            }

        private:
            void initialize()
            {
                const auto& schemas = get_all_schemas();
                for (auto it = schemas.begin(); it != schemas.end(); ++it) {
                    schema_error_t reference_error;
                    if (find_external_reference(it.value(), "#", reference_error)) {
                        setup_error_ = std::move(reference_error);
                        setup_error_.schema_fragment = it.key();
                        validators_.clear();
                        return;
                    }

                    try {
                        auto validator = std::make_unique<nlohmann::json_schema::json_validator>(
                            disabled_schema_loader(), nullptr, nullptr);
                        validator->set_root_schema(it.value());
                        validators_.emplace(it.key(), std::move(validator));
                    } catch (...) {
                        setup_error_ = {"(schema)", "schema validator initialization failed", it.key()};
                        validators_.clear();
                        return;
                    }
                }
            }

            std::once_flag initialization_once_;
            std::map<std::string, std::unique_ptr<nlohmann::json_schema::json_validator>> validators_;
            schema_error_t setup_error_;
        };
    }

    std::string validation_result_t::summary() const
    {
        if (valid)
            return "valid";

        std::ostringstream stream;
        stream << "validation failed with " << errors.size() << " error(s)";
        for (const auto& error : errors)
            stream << "; at " << error.path << ": " << error.message;
        return stream.str();
    }

    validation_result_t validate_tool_args(
        const std::string& tool_name,
        const json& args,
        const json& schema)
    {
        static_cast<void>(tool_name);
        if (!args.is_object())
            return make_failure("(root)", "arguments must be a JSON object", bounded_instance_fragment(args));
        return validate_with_schema(args, schema);
    }

    validation_result_t validate_tool_args(
        const std::string& tool_name,
        const json& args)
    {
        return schema_validator_registry::instance().validate(tool_name, args);
    }

    validation_result_t schema_validator_status()
    {
        return schema_validator_registry::instance().status();
    }

    void register_schema_validator()
    {
        schema_validator_registry::instance().register_schemas();
    }
}
