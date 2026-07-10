#include "cli.hpp"

#include <cstdlib>
#include <fmt/format.h>
#include <string>
#include <string_view>
#include <tuple>

namespace
{
    using x86Tester::Cli::Option;
    using x86Tester::Cli::Section;

    // clang-format off
    constexpr auto kOptions = std::make_tuple(
        Option<std::vector<std::string>>{ "--isa", "", "<ext>", Section::Selection, false, "Generate all mnemonics of an ISA extension (e.g. SSE2, BMI1)" },
        Option<std::vector<std::string>>{ "--category", "--cat", "<cat>", Section::Selection, false, "Generate all mnemonics of a category (e.g. BINARY, SSE)" },
        Option<std::vector<std::string>>{ "--exclude", "-x", "<mnemonic>", Section::Selection, false, "Exclude a mnemonic from the selection" },
        Option<std::filesystem::path>{ "--out", "-o", "<dir>", Section::Options, false, "Output directory (default: testdata)" },
        Option<unsigned>{ "--threads", "-j", "<n>", Section::Options, false, "Max worker threads (0 = use all cores, default)" },
        Option<bool>{ "--force", "-f", "", Section::Options, false, "Regenerate even if the output file already exists" },
        Option<bool>{ "--list", "-l", "", Section::Options, false, "List the selected mnemonics and exit" },
        Option<bool>{ "--stop-on-impossible", "", "", Section::Options, false, "Stop cleanly at the first impossible target (for fixing)" },
        Option<bool>{ "--validate-only", "", "", Section::Options, false, "Validate existing test data without generating new tests" },
        Option<bool>{ "--validate-full", "", "", Section::Options, false, "Validates every case, default validation does only 3 tests per group" },
        Option<bool>{ "--skip-validation", "", "", Section::Options, false, "Skip validation of generated test data (for speed)" },
        Option<bool>{ "--sandbox", "", "", Section::Options, true, "" },
        Option<bool>{ "--help", "-h", "", Section::Options, false, "Show this help" }
    );
    // clang-format on

    void printOption(std::string_view name, std::string_view metavar, std::string_view help)
    {
        std::string invocation(name);
        if (!metavar.empty())
        {
            invocation += ' ';
            invocation += metavar;
        }
        fmt::print("  {:<20}  {}\n", invocation, help);
    }

    template<typename... Ts> void printUsage(const std::tuple<Option<Ts>...>& def)
    {
        fmt::print("Usage: x86Tester-cli [options] [mnemonic ...]\n\n");

        fmt::print("Selection (default: all supported instructions):\n");
        fmt::print("  {:<20}  {}\n", "<mnemonic>", "Generate the named mnemonic (e.g. lea add)");
        std::apply(
            [](const auto&... opt) {
                ((opt.section == Section::Selection && !opt.hidden ? printOption(opt.name, opt.metavar, opt.help) : void()),
                 ...);
            },
            def);

        fmt::print("\nOptions:\n");
        std::apply(
            [](const auto&... opt) {
                ((opt.section == Section::Options && !opt.hidden ? printOption(opt.name, opt.metavar, opt.help) : void()),
                 ...);
            },
            def);
    }
}

int main(int argc, char** argv)
{
    using namespace x86Tester;

    auto result = Cli::parse(argc, argv, kOptions);
    if (!result.ok)
    {
        printUsage(kOptions);
        return EXIT_FAILURE;
    }

    auto& [isa, category, exclude, out, threads, force, list, stopImpossible, validateOnly, validateFull,
           skipValidation, sandbox, help] = result.values;

    if (help)
    {
        printUsage(kOptions);
        return EXIT_SUCCESS;
    }

    if (sandbox)
        return runSandbox();

    const GeneratorOptions options{
        std::move(result.positional),
        std::move(isa),
        std::move(category),
        std::move(exclude),
        out.empty() ? std::filesystem::path{ "testdata" } : std::move(out),
        force,
        list,
        stopImpossible,
        validateOnly,
        skipValidation,
        validateFull,
        threads,
    };

    return runGenerator(options);
}
