#pragma once

#include <charconv>
#include <cstddef>
#include <filesystem>
#include <fmt/format.h>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>
#include <x86Tester/logging.hpp>

namespace x86Tester
{
    struct GeneratorOptions
    {
        std::vector<std::string> mnemonicNames;
        std::vector<std::string> isaNames;
        std::vector<std::string> categoryNames;
        std::vector<std::string> excludeNames;
        std::filesystem::path outputPath{ "testdata" };
        bool force{};
        bool showList{};
        bool stopOnImpossible{};
        bool validateOnly{};
        bool skipValidation{};
        bool validateFull{};
        unsigned maxThreads{};
    };

    int runGenerator(const GeneratorOptions& options);

    int runSandbox();

    namespace Cli
    {
        enum class Section
        {
            Selection,
            Options,
        };

        template<typename T> struct Option
        {
            std::string_view name;
            std::string_view alias;
            std::string_view metavar;
            Section section;
            bool hidden;
            std::string_view help;
        };

        template<typename... Ts> struct ParseResult
        {
            bool ok = true;
            std::vector<std::string> positional;
            std::tuple<Ts...> values;
        };

        template<typename T> struct IsStringList : std::false_type
        {
        };
        template<> struct IsStringList<std::vector<std::string>> : std::true_type
        {
        };

        template<typename T> bool convertValue(std::string_view s, T& out)
        {
            if constexpr (std::is_same_v<T, std::string>)
            {
                out = std::string(s);
                return true;
            }
            else if constexpr (std::is_same_v<T, std::filesystem::path>)
            {
                out = std::filesystem::path(std::string(s));
                return true;
            }
            else
            {
                const auto res = std::from_chars(s.data(), s.data() + s.size(), out);
                return res.ec == std::errc{} && res.ptr == s.data() + s.size();
            }
        }

        template<typename Opt> bool matchesOption(const Opt& opt, std::string_view arg)
        {
            return arg == opt.name || (!opt.alias.empty() && arg == opt.alias);
        }

        template<std::size_t I, typename Def, typename Values>
        bool tryOption(const Def& def, Values& values, std::string_view arg, int& i, int argc, char** argv, bool& error)
        {
            const auto& opt = std::get<I>(def);
            if (!matchesOption(opt, arg))
                return false;

            using T = std::tuple_element_t<I, Values>;
            if constexpr (std::is_same_v<T, bool>)
            {
                std::get<I>(values) = true;
            }
            else
            {
                if (i + 1 >= argc)
                {
                    Logging::println("Missing value for {}", arg);
                    error = true;
                    return true;
                }

                const std::string_view value = argv[++i];
                if constexpr (IsStringList<T>::value)
                {
                    std::get<I>(values).emplace_back(value);
                }
                else
                {
                    T out{};
                    if (!convertValue(value, out))
                    {
                        Logging::println("Invalid value for {}: {}", arg, value);
                        error = true;
                        return true;
                    }
                    std::get<I>(values) = out;
                }
            }
            return true;
        }

        template<typename Def, typename Values, std::size_t... I>
        bool dispatchOption(
            const Def& def, Values& values, std::string_view arg, int& i, int argc, char** argv, bool& error,
            std::index_sequence<I...>)
        {
            return (tryOption<I>(def, values, arg, i, argc, argv, error) || ...);
        }

        template<typename... Ts> ParseResult<Ts...> parse(int argc, char** argv, const std::tuple<Option<Ts>...>& def)
        {
            ParseResult<Ts...> result;

            for (int i = 1; i < argc; ++i)
            {
                const std::string_view arg = argv[i];

                if (!arg.starts_with('-'))
                {
                    result.positional.emplace_back(arg);
                    continue;
                }

                bool error = false;
                const bool matched = dispatchOption(
                    def, result.values, arg, i, argc, argv, error, std::index_sequence_for<Ts...>{});

                if (!matched)
                {
                    Logging::println("Unknown option: {}", arg);
                    result.ok = false;
                    return result;
                }
                if (error)
                {
                    result.ok = false;
                    return result;
                }
            }

            return result;
        }
    }
}
