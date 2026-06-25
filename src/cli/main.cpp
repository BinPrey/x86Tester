#include "utils.hpp"

#include <Zydis/Disassembler.h>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fmt/format.h>
#include <fmt/ostream.h>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <ranges>
#include <set>
#include <sfl/small_flat_map.hpp>
#include <sfl/small_flat_set.hpp>
#include <sfl/small_vector.hpp>
#include <sfl/static_vector.hpp>
#include <sfl/vector.hpp>
#include <string>
#include <string_view>
#include <x86Tester/cpuid.hpp>
#include <x86Tester/generator.hpp>
#include <x86Tester/logging.hpp>

using namespace x86Tester;
using namespace x86Tester::Generator;

static ZydisDisassembledInstruction disassembleInstruction(
    ZydisMachineMode mode, const std::span<const std::uint8_t> instrData, std::uint64_t address)
{
    ZydisDisassembledInstruction instr{};
    ZydisDisassembleIntel(mode, address, instrData.data(), instrData.size(), &instr);
    return instr;
}

static std::filesystem::path getPathForMnemonic(ZydisMnemonic mnemonic, const std::filesystem::path& outputPath)
{
    if (!std::filesystem::exists(outputPath))
    {
        if (!std::filesystem::create_directories(outputPath))
        {
            fmt::print("Failed to create output directory\n");
            std::abort();
        }
    }

    const auto filePath = outputPath / (ZydisMnemonicGetString(mnemonic) + std::string(".txt"));
    return filePath;
}

static bool serializeTestEntries(
    ZydisMachineMode mode, ZydisMnemonic mnemonic, const std::vector<InstrTestGroup>& entries,
    const std::filesystem::path& outputPath)
{
    const auto filePath = getPathForMnemonic(mnemonic, outputPath);

    std::ofstream file(filePath);
    if (!file)
    {
        fmt::print("Failed to open file for writing\n");
        return false;
    }

    const auto getExceptionString = [](ExceptionType exception) -> std::string {
        switch (exception)
        {
            case ExceptionType::None:
                return "NONE";
            case ExceptionType::DivideError:
                return "INT_DIVIDE_ERROR";
            case ExceptionType::IntegerOverflow:
                return "INT_OVERFLOW";
        }
        return "<ERROR>";
    };

    std::vector<std::string> dataPool;
    std::map<std::string, std::size_t> dataIndex;

    const auto intern = [&](std::string hex) -> std::size_t {
        if (auto it = dataIndex.find(hex); it != dataIndex.end())
            return it->second;
        const auto idx = dataPool.size();
        dataIndex.emplace(hex, idx);
        dataPool.push_back(std::move(hex));
        return idx;
    };

    const auto internFlags = [&](std::uint32_t flags) {
        std::array<std::uint8_t, 4> flagsHex{};
        std::memcpy(flagsHex.data(), &flags, 4);
        return intern(Utils::hexEncode(flagsHex));
    };

    const auto buildSchema = [](const std::set<ZydisRegister>& regs, bool hasFlags) {
        std::string s;
        for (const auto reg : regs)
        {
            if (!s.empty())
                s += ",";
            s += ZydisRegisterGetString(reg);
        }
        if (hasFlags)
        {
            if (!s.empty())
                s += ",";
            s += "flags";
        }
        return s;
    };

    std::string body;

    for (const auto& group : entries)
    {
        const auto instr = disassembleInstruction(mode, group.instrData, group.address);

        std::set<ZydisRegister> inRegs;
        std::set<ZydisRegister> outRegs;
        bool inHasFlags = false;
        bool outHasFlags = false;
        for (const auto& entry : group.entries)
        {
            for (const auto& [reg, data] : entry.inputRegs)
                inRegs.insert(reg);
            for (const auto& [reg, data] : entry.outputRegs)
                outRegs.insert(reg);
            inHasFlags = inHasFlags || entry.inputFlags.has_value();
            outHasFlags = outHasFlags || entry.outputFlags.has_value();
        }

        body += fmt::format(
            "instr:0x{:X};#{};{};{};in={};out={}\n", group.address, Utils::hexEncode(group.instrData), instr.text,
            group.entries.size(), buildSchema(inRegs, inHasFlags), buildSchema(outRegs, outHasFlags));

        for (const auto& entry : group.entries)
        {
            std::string row;

            for (const auto reg : inRegs)
            {
                if (!row.empty())
                    row += ",";
                const auto it = entry.inputRegs.find(reg);
                row += fmt::format("{}", intern(Utils::hexEncode({ it->second.data(), it->second.size() })));
            }
            if (inHasFlags)
            {
                if (!row.empty())
                    row += ",";
                row += fmt::format("{}", internFlags(entry.inputFlags.value_or(0)));
            }

            row += "|";

            if (entry.exceptionType)
            {
                row += fmt::format("!{}", getExceptionString(*entry.exceptionType));
            }
            else
            {
                bool firstOut = true;
                for (const auto reg : outRegs)
                {
                    if (!firstOut)
                        row += ",";
                    firstOut = false;
                    const auto it = entry.outputRegs.find(reg);
                    row += fmt::format("{}", intern(Utils::hexEncode({ it->second.data(), it->second.size() })));
                }
                if (outHasFlags)
                {
                    if (!firstOut)
                        row += ",";
                    row += fmt::format("{}", internFlags(entry.outputFlags.value_or(0)));
                }
            }

            body += row;
            body += "\n";
        }
    }

    fmt::print(file, "data:{}\n", dataPool.size());
    for (const auto& hex : dataPool)
    {
        fmt::print(file, "#{}\n", hex);
    }

    file << body;

    return true;
}

static std::optional<std::size_t> generateInstrTests(
    ZydisMachineMode mode, ZydisMnemonic mnemonic, const std::filesystem::path& outputPath, bool force, std::size_t index,
    std::size_t total)
{
    const auto filePath = getPathForMnemonic(mnemonic, outputPath);
    const double pct = total > 0 ? (100.0 * (index + 1) / static_cast<double>(total)) : 0.0;

    if (!force && std::filesystem::exists(filePath))
    {
        fmt::print("[{}/{} {:5.1f}%] {} (skipped)\n", index + 1, total, pct, ZydisMnemonicGetString(mnemonic));
        return std::nullopt;
    }

    fmt::print("[{}/{} {:5.1f}%] {}\n", index + 1, total, pct, ZydisMnemonicGetString(mnemonic));

    const auto filter = Generator::Filter{}.addMnemonics(mnemonic);

    Logging::startProgress(
        "Building \"{}\" instruction combinations", ZydisMnemonicGetString(static_cast<ZydisMnemonic>(mnemonic)));

    const auto instrs = Generator::buildInstructions(
        mode, filter, true, [](auto curVal, auto maxVal) { Logging::updateProgress(curVal, maxVal); });

    Logging::endProgress();

    const auto numInstrs = instrs.entryOffsets.size();
    Logging::println("Total instructions: {}", numInstrs);

    Logging::startProgress("Generating tests");

    std::vector<InstrTestGroup> testGroups;
    std::mutex mtx;
    std::atomic<size_t> curInstr = 0;

    instrs.forEachParallel([&](auto&& instrData) {
        //
        InstrTestGroup testCase = generateInstructionTestData(mode, instrData);
        if (!testCase.entries.empty() && !testCase.illegalInstruction)
        {
            std::lock_guard lock(mtx);
            testGroups.push_back(std::move(testCase));
        }
        Logging::updateProgress(++curInstr, numInstrs);
    });

    Logging::endProgress();

    if (Generator::stopRequested())
        return 0;

    // Sort the groups by instruction operand width.
    std::sort(testGroups.begin(), testGroups.end(), [mode](const auto& a, const auto& b) {
        const auto instA = disassembleInstruction(mode, a.instrData, a.address);
        const auto instB = disassembleInstruction(mode, b.instrData, b.address);
        return instA.info.operand_width < instB.info.operand_width;
    });

    // Group the test cases by instruction.
    std::map<ZydisMnemonic, std::vector<InstrTestGroup>> testGroupsMap;
    for (auto& testGroup : testGroups)
    {
        const auto instr = disassembleInstruction(mode, testGroup.instrData, testGroup.address);

        auto it = testGroupsMap.find(instr.info.mnemonic);
        if (it != testGroupsMap.end())
        {
            it->second.push_back(std::move(testGroup));
            continue;
        }
        else
        {
            testGroupsMap.insert({ instr.info.mnemonic, { std::move(testGroup) } });
        }
    }

    // Report results.
    size_t totalTestEntries = 0;
    for (const auto& [mnemonic, testGroups] : testGroupsMap)
    {
        for (auto& testGroup : testGroups)
        {
            totalTestEntries += testGroup.entries.size();
        }
    }
    Logging::println("Total test cases: {}", totalTestEntries);

    // Save to file.
    for (const auto& [groupMnemonic, testGroups] : testGroupsMap)
    {
        serializeTestEntries(mode, groupMnemonic, { testGroups }, outputPath);
    }

    return totalTestEntries;
}

static bool iequals(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

static std::optional<ZydisMnemonic> resolveMnemonic(std::string_view name)
{
    for (int m = ZYDIS_MNEMONIC_INVALID + 1; m <= ZYDIS_MNEMONIC_MAX_VALUE; ++m)
    {
        if (iequals(name, ZydisMnemonicGetString(static_cast<ZydisMnemonic>(m))))
            return static_cast<ZydisMnemonic>(m);
    }
    return std::nullopt;
}

static std::optional<ZydisISAExt> resolveIsaExt(std::string_view name)
{
    for (int i = 0; i <= ZYDIS_ISA_EXT_MAX_VALUE; ++i)
    {
        if (iequals(name, ZydisISAExtGetString(static_cast<ZydisISAExt>(i))))
            return static_cast<ZydisISAExt>(i);
    }
    return std::nullopt;
}

static std::optional<ZydisInstructionCategory> resolveCategory(std::string_view name)
{
    for (int i = 0; i <= ZYDIS_CATEGORY_MAX_VALUE; ++i)
    {
        if (iequals(name, ZydisCategoryGetString(static_cast<ZydisInstructionCategory>(i))))
            return static_cast<ZydisInstructionCategory>(i);
    }
    return std::nullopt;
}

static void printUsage()
{
    fmt::print("Usage: x86Tester-cli [options] [mnemonic ...]\n"
               "\n"
               "Selection (default: all supported instructions):\n"
               "  <mnemonic>            Generate the named mnemonic (e.g. lea add)\n"
               "  --isa <ext>           Generate all mnemonics of an ISA extension (e.g. SSE2, BMI1)\n"
               "  --category <cat>      Generate all mnemonics of a category (e.g. BINARY, SSE)\n"
               "  --exclude <mnemonic>  Exclude a mnemonic from the selection\n"
               "\n"
               "Options:\n"
               "  --out <dir>           Output directory (default: testdata)\n"
               "  --force               Regenerate even if the output file already exists\n"
               "  --list                List the selected mnemonics and exit\n"
               "  --stop-on-impossible  Stop cleanly at the first impossible target (for fixing)\n"
               "  --help                Show this help\n");
}

int main(int argc, char** argv)
{
    std::vector<std::string> mnemonicNames;
    std::vector<std::string> isaNames;
    std::vector<std::string> categoryNames;
    std::vector<std::string> excludeNames;
    std::filesystem::path outputPath = "testdata";
    bool force = false;
    bool list = false;
    bool stopOnImpossible = false;

    const auto nextArg = [&](int& i) -> std::string {
        if (i + 1 >= argc)
        {
            fmt::print("Missing value for {}\n", argv[i]);
            std::exit(EXIT_FAILURE);
        }
        return argv[++i];
    };

    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h")
        {
            printUsage();
            return EXIT_SUCCESS;
        }
        else if (arg == "--out" || arg == "-o")
            outputPath = nextArg(i);
        else if (arg == "--isa")
            isaNames.push_back(nextArg(i));
        else if (arg == "--category" || arg == "--cat")
            categoryNames.push_back(nextArg(i));
        else if (arg == "--exclude" || arg == "-x")
            excludeNames.push_back(nextArg(i));
        else if (arg == "--force" || arg == "-f")
            force = true;
        else if (arg == "--list" || arg == "-l")
            list = true;
        else if (arg == "--stop-on-impossible")
            stopOnImpossible = true;
        else if (arg.starts_with("-"))
        {
            fmt::print("Unknown option: {}\n", arg);
            printUsage();
            return EXIT_FAILURE;
        }
        else
            mnemonicNames.push_back(arg);
    }

    const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;

    std::set<ZydisISAExt> isaExts;
    for (const auto& name : isaNames)
    {
        if (auto e = resolveIsaExt(name))
            isaExts.insert(*e);
        else
        {
            fmt::print("Unknown ISA extension: {}\n", name);
            return EXIT_FAILURE;
        }
    }

    std::set<ZydisInstructionCategory> categories;
    for (const auto& name : categoryNames)
    {
        if (auto c = resolveCategory(name))
            categories.insert(*c);
        else
        {
            fmt::print("Unknown category: {}\n", name);
            return EXIT_FAILURE;
        }
    }

    std::set<ZydisMnemonic> excluded;
    for (const auto& name : excludeNames)
    {
        if (auto m = resolveMnemonic(name))
            excluded.insert(*m);
        else
        {
            fmt::print("Unknown mnemonic (exclude): {}\n", name);
            return EXIT_FAILURE;
        }
    }

    const auto index = Generator::buildMnemonicIndex(mode);

    std::set<ZydisMnemonic> selected;

    const bool selectAll = mnemonicNames.empty() && isaExts.empty() && categories.empty();
    if (selectAll)
    {
        for (int m = ZYDIS_MNEMONIC_INVALID + 1; m <= ZYDIS_MNEMONIC_MAX_VALUE; ++m)
        {
            if (index[m].encodable)
                selected.insert(static_cast<ZydisMnemonic>(m));
        }
    }
    else
    {
        for (const auto& name : mnemonicNames)
        {
            if (auto m = resolveMnemonic(name))
                selected.insert(*m);
            else
            {
                fmt::print("Unknown mnemonic: {}\n", name);
                return EXIT_FAILURE;
            }
        }
        for (int m = ZYDIS_MNEMONIC_INVALID + 1; m <= ZYDIS_MNEMONIC_MAX_VALUE; ++m)
        {
            if (!index[m].encodable)
                continue;
            if (isaExts.count(index[m].isaExt) != 0 || categories.count(index[m].category) != 0)
                selected.insert(static_cast<ZydisMnemonic>(m));
        }
    }

    std::vector<ZydisMnemonic> finalList;
    for (const auto m : selected)
    {
        if (excluded.count(m) != 0)
            continue;
        if (index[m].encodable && !Generator::isSupportedCategory(index[m].category))
            continue;
        // The intentionally-undefined opcodes have encodings that disassemble inconsistently and
        // destabilize generation; never build them.
        if (m == ZYDIS_MNEMONIC_UD0 || m == ZYDIS_MNEMONIC_UD1 || m == ZYDIS_MNEMONIC_UD2)
            continue;
        if (!Generator::isSupportedIsaExt(index[m].isaExt))
            continue;
        finalList.push_back(m);
    }

    if (list)
    {
        for (const auto m : finalList)
            fmt::print("{}\n", ZydisMnemonicGetString(m));
        fmt::print("Total: {} mnemonics\n", finalList.size());
        return EXIT_SUCCESS;
    }

    const auto& cpu = Cpuid::getCpuInfo();
    outputPath /= fmt::format("{}_f{}m{}s{}", cpu.name, cpu.family, cpu.model, cpu.stepping);
    fmt::print("Output directory: {}\n", outputPath.string());

    Generator::setStopOnImpossible(stopOnImpossible);

    const auto startTime = std::chrono::steady_clock::now();
    std::size_t totalTests = 0;
    std::size_t generated = 0;
    std::size_t skipped = 0;
    for (std::size_t i = 0; i < finalList.size(); ++i)
    {
        const auto tests = generateInstrTests(mode, finalList[i], outputPath, force, i, finalList.size());
        if (tests.has_value())
        {
            ++generated;
            totalTests += *tests;
        }
        else
        {
            ++skipped;
        }
        if (Generator::stopRequested())
        {
            fmt::print("\nStopped at first impossible target:\n{}\n", Generator::takeImpossibleReport());
            break;
        }
    }

    const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - startTime).count();
    fmt::print(
        "Done: {} generated, {} skipped (of {} mnemonics), {} test cases, {:.1f}s\n", generated, skipped, finalList.size(),
        totalTests, elapsed);

    return EXIT_SUCCESS;
}
