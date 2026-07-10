#include "cli.hpp"
#include "utils.hpp"

#include <Zydis/Disassembler.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <deque>
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
#include <x86Tester/execution.hpp>
#include <x86Tester/generator.hpp>
#include <x86Tester/logging.hpp>
#include <x86Tester/parallel.hpp>

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
            Logging::println("Failed to create output directory");
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
        Logging::println("Failed to open file for writing");
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
    const std::string mnemonicStr = ZydisMnemonicGetString(mnemonic);
    Logging::startProgress("Building instruction combinations...");

    const auto instrs = Generator::buildInstructions(
        mode, mnemonic, true, [](auto curVal, auto maxVal) { Logging::updateProgress(curVal, maxVal); });

    const auto numInstrs = instrs.entryOffsets.size();
    if (numInstrs == 0)
        Logging::println("No instructions generated, unsupported by host or memory access.");
    else
        Logging::println("Total instructions: {}", numInstrs);

    Logging::endProgress();

    if (numInstrs == 0)
    {
        return std::nullopt;
    }

    Logging::startProgress("Generating tests...");

    std::vector<InstrTestGroup> testGroups;
    std::size_t totalIterations = 0;

    auto allGroups = Generator::generateGroupedTestData(
        mode, instrs, [](auto curVal, auto maxVal) { Logging::updateProgress(curVal, maxVal); });

    for (auto& testCase : allGroups)
    {
        if (!testCase.entries.empty() && !testCase.illegalInstruction)
        {
            Logging::addTitleCases(testCase.entries.size());
            totalIterations += testCase.totalAttempts;
            testGroups.push_back(std::move(testCase));
        }
    }

    Logging::endProgress();

    if (Generator::stopRequested())
        return 0;

    // Sort the groups by instruction operand width.
    std::sort(testGroups.begin(), testGroups.end(), [mode](const auto& a, const auto& b) {
        const auto instA = disassembleInstruction(mode, a.instrData, a.address);
        const auto instB = disassembleInstruction(mode, b.instrData, b.address);
        if (instA.info.operand_width != instB.info.operand_width)
            return instA.info.operand_width < instB.info.operand_width;
        return std::lexicographical_compare(
            a.instrData.begin(), a.instrData.end(), b.instrData.begin(), b.instrData.end());
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
    Logging::println("Total test cases: {}, total iterations {}", totalTestEntries, totalIterations);

    // Save to file.
    for (const auto& [groupMnemonic, testGroups] : testGroupsMap)
    {
        serializeTestEntries(mode, groupMnemonic, { testGroups }, outputPath);
    }

    return totalTestEntries;
}

static std::vector<ZydisMnemonic> generateTests(
    const std::vector<ZydisMnemonic>& finalList, const ZydisMachineMode mode, const std::filesystem::path& outputPath,
    bool force)
{
    std::vector<ZydisMnemonic> generated;

    const auto startTime = std::chrono::steady_clock::now();
    std::size_t totalTests = 0;
    std::size_t skipped = 0;

    Logging::startProgress("Generating tests...");
    for (std::size_t i = 0; i < finalList.size(); ++i)
    {
        const auto mnemonic = finalList[i];
        const auto* mnemonicStr = ZydisMnemonicGetString(mnemonic);

        Logging::setTitleStatus(fmt::format("{}/{} | {}", i + 1, finalList.size(), mnemonicStr));
        Logging::updateProgress(i + 1, finalList.size());

        const auto filePath = getPathForMnemonic(mnemonic, outputPath);
        if (!force && std::filesystem::exists(filePath))
        {
            Logging::println("Skipping {}, already exists", mnemonicStr);
            ++skipped;
            continue;
        }

        Logging::startProgress("Generating test data for {}...", mnemonicStr);

        const auto tests = generateInstrTests(mode, finalList[i], outputPath, force, i, finalList.size());
        if (tests.has_value())
        {
            generated.push_back(finalList[i]);
            totalTests += *tests;
        }
        else
        {
            ++skipped;
        }

        Logging::endProgress();

        if (Generator::stopRequested())
        {
            Logging::println("Stopped at first impossible target:\n{}", Generator::takeImpossibleReport());
            break;
        }
    }
    Logging::endProgress();

    const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - startTime).count();
    Logging::println(
        "Done: {} generated, {} skipped (of {} mnemonics), {} test cases, {:.1f}s", generated.size(), skipped, finalList.size(),
        totalTests, elapsed);

    return generated;
}

static bool deserializeTestEntries(
    const std::filesystem::path& inputFile, std::vector<InstrTestGroup>& groups,
    std::deque<std::vector<std::uint8_t>>& instrStore)
{
    std::ifstream file(inputFile);
    if (!file)
        return false;

    std::vector<std::string> lines;
    for (std::string line; std::getline(file, line);)
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        lines.push_back(std::move(line));
    }

    const auto split = [](std::string_view s, char delim) {
        std::vector<std::string_view> out;
        std::size_t start = 0;
        while (true)
        {
            const auto pos = s.find(delim, start);
            if (pos == std::string_view::npos)
            {
                out.push_back(s.substr(start));
                break;
            }
            out.push_back(s.substr(start, pos - start));
            start = pos + 1;
        }
        return out;
    };

    const auto parseException = [](std::string_view name) -> std::optional<ExceptionType> {
        if (name == "NONE")
            return ExceptionType::None;
        if (name == "INT_DIVIDE_ERROR")
            return ExceptionType::DivideError;
        if (name == "INT_OVERFLOW")
            return ExceptionType::IntegerOverflow;
        return std::nullopt;
    };

    std::size_t cursor = 0;
    if (cursor >= lines.size() || lines[cursor].rfind("data:", 0) != 0)
        return false;

    const std::size_t poolCount = std::strtoull(lines[cursor].c_str() + 5, nullptr, 10);
    ++cursor;

    std::vector<std::vector<std::uint8_t>> pool;
    pool.reserve(poolCount);
    for (std::size_t i = 0; i < poolCount; ++i)
    {
        if (cursor >= lines.size() || lines[cursor].empty() || lines[cursor][0] != '#')
            return false;
        pool.push_back(Utils::hexDecode(std::string_view(lines[cursor]).substr(1)));
        ++cursor;
    }

    const auto poolFlags = [&](std::size_t idx) -> std::uint32_t {
        std::uint32_t flags = 0;
        if (idx < pool.size())
            std::memcpy(&flags, pool[idx].data(), std::min<std::size_t>(pool[idx].size(), 4));
        return flags;
    };

    const auto parseSchema = [&](std::string_view field) {
        const auto eq = field.find('=');
        const auto body = eq == std::string_view::npos ? field : field.substr(eq + 1);
        std::vector<std::string_view> tokens;
        if (!body.empty())
            tokens = split(body, ',');
        return tokens;
    };

    while (cursor < lines.size())
    {
        if (lines[cursor].empty())
        {
            ++cursor;
            continue;
        }
        if (lines[cursor].rfind("instr:", 0) != 0)
            return false;

        const auto header = split(lines[cursor], ';');
        ++cursor;
        if (header.size() < 6)
            return false;

        InstrTestGroup group{};

        const auto addrField = header[0];
        group.address = std::strtoull(std::string(addrField.substr(addrField.find("0x") + 2)).c_str(), nullptr, 16);

        instrStore.push_back(Utils::hexDecode(header[1].substr(1)));
        group.instrData = std::span<const std::uint8_t>(instrStore.back());

        const std::size_t count = std::strtoull(std::string(header[3]).c_str(), nullptr, 10);
        const auto inSchema = parseSchema(header[4]);
        const auto outSchema = parseSchema(header[5]);

        const auto applySide = [&](std::string_view idxList, const std::vector<std::string_view>& schema,
                                   sfl::small_flat_map<ZydisRegister, RegTestData, 2>& regs,
                                   std::optional<std::uint32_t>& flagsOut) -> bool {
            std::vector<std::string_view> idxTokens;
            if (!idxList.empty())
                idxTokens = split(idxList, ',');
            if (idxTokens.size() != schema.size())
                return false;
            for (std::size_t i = 0; i < schema.size(); ++i)
            {
                const std::size_t idx = std::strtoull(std::string(idxTokens[i]).c_str(), nullptr, 10);
                if (idx >= pool.size())
                    return false;
                if (schema[i] == "flags")
                {
                    flagsOut = poolFlags(idx);
                }
                else
                {
                    const auto reg = Utils::resolveRegister(schema[i]);
                    if (!reg)
                        return false;
                    regs[*reg] = RegTestData{ pool[idx].begin(), pool[idx].end() };
                }
            }
            return true;
        };

        group.entries.reserve(count);
        for (std::size_t r = 0; r < count; ++r)
        {
            if (cursor >= lines.size())
                return false;
            const auto sides = split(lines[cursor], '|');
            ++cursor;
            if (sides.size() != 2)
                return false;

            TestCaseEntry entry{};
            if (!applySide(sides[0], inSchema, entry.inputRegs, entry.inputFlags))
                return false;

            if (!sides[1].empty() && sides[1][0] == '!')
            {
                const auto exc = parseException(sides[1].substr(1));
                if (!exc)
                    return false;
                entry.exceptionType = *exc;
            }
            else if (!applySide(sides[1], outSchema, entry.outputRegs, entry.outputFlags))
            {
                return false;
            }

            group.entries.push_back(std::move(entry));
        }

        groups.push_back(std::move(group));
    }

    return true;
}

struct GroupReport
{
    ZydisMnemonic mnemonic;
    std::size_t totalEntries = 0;
    std::size_t failures = 0;
    std::string instructionText;
    std::vector<std::string> failureDetails;
    bool failed{};
};

static GroupReport validateTestEntries(
    ZydisMachineMode mode, const InstrTestGroup& group, std::size_t maxReport, bool validateFull)
{
    GroupReport report{};

    const auto dis = disassembleInstruction(mode, group.instrData, group.address);
    report.instructionText = std::format("{} [{}]", dis.text, Utils::hexEncode(group.instrData));

    std::uint32_t detFlagMask = 0;
    if (dis.info.cpu_flags != nullptr)
    {
        const auto* cf = dis.info.cpu_flags;
        detFlagMask = (cf->modified | cf->set_0 | cf->set_1) & ~cf->undefined;
    }

    {
        const auto expectedOutVec = Generator::getWrittenRegisters(dis);
        const auto expectedInVec = Generator::getReadRegisters(dis);
        const std::set<ZydisRegister> expectedOut(expectedOutVec.begin(), expectedOutVec.end());
        const std::set<ZydisRegister> expectedIn(expectedInVec.begin(), expectedInVec.end());

        std::set<ZydisRegister> recordedOut;
        std::set<ZydisRegister> recordedIn;
        bool anyResultEntry = false;
        for (const auto& entry : group.entries)
        {
            for (const auto& [reg, bytes] : entry.inputRegs)
                recordedIn.insert(reg);
            if (entry.exceptionType && *entry.exceptionType != ExceptionType::None)
                continue;
            anyResultEntry = true;
            for (const auto& [reg, bytes] : entry.outputRegs)
                recordedOut.insert(reg);
        }

        const auto regSetStr = [](const std::set<ZydisRegister>& regs) {
            std::string s;
            for (const auto reg : regs)
            {
                if (!s.empty())
                    s += ",";
                s += ZydisRegisterGetString(reg);
            }
            return s.empty() ? std::string("<none>") : s;
        };

        if (anyResultEntry && recordedOut != expectedOut)
            report.failureDetails.push_back(
                fmt::format("out schema mismatch: expected {{{}}} got {{{}}}", regSetStr(expectedOut), regSetStr(recordedOut)));
        if (recordedIn != expectedIn)
            report.failureDetails.push_back(
                fmt::format("in schema mismatch: expected {{{}}} got {{{}}}", regSetStr(expectedIn), regSetStr(recordedIn)));
    }

    Execution::ScopedContext ctx(mode, group.instrData);
    if (!ctx)
    {
        report.failed = true;
        return report;
    }

    if (dis.info.mnemonic == ZYDIS_MNEMONIC_CPUID)
        ctx.pinThread(0);

    // This should be sufficient to see if it is malformed or correct.
    constexpr size_t partialValidationCount = 3;

    const size_t maxEntries = validateFull ? group.entries.size()
                                           : std::min<size_t>(partialValidationCount, group.entries.size());

    for (size_t i = 0; i < maxEntries; ++i)
    {
        const auto& entry = group.entries[i];

        for (const auto& [reg, bytes] : entry.inputRegs)
            ctx.setRegBytes(reg, std::span<const std::uint8_t>{ bytes.data(), bytes.size() });
        ctx.setRegValue(ZYDIS_REGISTER_EFLAGS, entry.inputFlags.value_or(0));

        const bool ran = ctx.execute();
        const auto status = ctx.getExecutionStatus();
        const bool expectException = entry.exceptionType && *entry.exceptionType != ExceptionType::None;

        std::string reason;

        if (expectException)
        {
            const bool match = (*entry.exceptionType == ExceptionType::DivideError
                                && status == Execution::ExecutionStatus::ExceptionIntDivideError)
                || (*entry.exceptionType == ExceptionType::IntegerOverflow
                    && status == Execution::ExecutionStatus::ExceptionIntOverflow);
            if (!match)
                reason = fmt::format("expected exception, status={}", static_cast<int>(status));
        }
        else if (!ran || status != Execution::ExecutionStatus::Success)
        {
            reason = fmt::format("unexpected fault, status={}", static_cast<int>(status));
        }
        else
        {
            for (const auto& [reg, expected] : entry.outputRegs)
            {
                const auto actual = ctx.getRegBytes(reg);
                if (actual.size() < expected.size() || !std::equal(expected.begin(), expected.end(), actual.begin()))
                {
                    reason = fmt::format(
                        "{}: expected {} got {}", ZydisRegisterGetString(reg),
                        Utils::hexEncode({ expected.data(), expected.size() }),
                        Utils::hexEncode({ actual.data(), std::min(actual.size(), expected.size()) }));
                    break;
                }
            }
            if (reason.empty() && entry.outputFlags && detFlagMask != 0)
            {
                const auto actualFlags = ctx.getRegValue<std::uint32_t>(ZYDIS_REGISTER_EFLAGS);
                if ((actualFlags & detFlagMask) != (*entry.outputFlags & detFlagMask))
                    reason = fmt::format(
                        "flags: expected {:08X} got {:08X} (mask {:08X})", *entry.outputFlags & detFlagMask,
                        actualFlags & detFlagMask, detFlagMask);
            }
        }

        if (!reason.empty())
        {
            report.failureDetails.push_back(std::move(reason));
        }
    }

    return report;
}

static void validateTests(
    const std::vector<ZydisMnemonic>& finalList, const ZydisMachineMode mode, const std::filesystem::path& outputPath,
    bool validateFull)
{
    std::size_t totalEntries = 0;
    std::size_t totalFailures = 0;
    std::size_t filesMissing = 0;
    std::size_t filesUnreadable = 0;
    std::mutex failureReportMtx;

    Logging::startProgress("Validating tests...");

    for (size_t i = 0; i < finalList.size(); ++i)
    {
        Logging::updateProgress(i + 1, finalList.size());

        const auto mnemonic = finalList[i];
        Logging::setTitleStatus(fmt::format("{}/{} | {}", i + 1, finalList.size(), ZydisMnemonicGetString(mnemonic)));

        const auto filePath = getPathForMnemonic(mnemonic, outputPath);
        if (!std::filesystem::exists(filePath))
        {
            Logging::println("Missing test data for mnemonic: {}", ZydisMnemonicGetString(mnemonic));
            ++filesMissing;
            continue;
        }

        std::vector<InstrTestGroup> groups;
        std::deque<std::vector<std::uint8_t>> instrStore;
        if (!deserializeTestEntries(filePath, groups, instrStore))
        {
            Logging::println("Failed to deserialize test data for mnemonic: {}", ZydisMnemonicGetString(mnemonic));
            ++filesUnreadable;
            continue;
        }

        std::size_t failures = 0;
        std::size_t entries = 0;
        std::atomic<bool> abort = false;

        std::vector<GroupReport> groupDetails;

        Logging::startProgress("Validating test data for for {}", ZydisMnemonicGetString(mnemonic));
        std::size_t n = 0;
        parallelForEach(groups, [&](const auto& group) {
            if (abort.load())
                return;

            entries += group.entries.size();

            const auto report = validateTestEntries(mode, group, 20, validateFull);
            if (report.failed)
            {
                abort = true;
                return;
            }

            failures += report.failureDetails.size();

            if (!report.failureDetails.empty())
            {
                std::lock_guard lock(failureReportMtx);
                groupDetails.push_back(std::move(report));
            }

            Logging::updateProgress(++n, groups.size());
        });
        Logging::endProgress();

        if (abort)
        {
            Logging::println("Aborted validation due to execution failure");
            break;
        }

        totalEntries += entries;
        totalFailures += failures;

        if (failures != 0)
        {
            for (const auto& detail : groupDetails)
            {
                Logging::println("  Failures for {}", detail.instructionText);
                for (const auto& reason : detail.failureDetails)
                {
                    Logging::println("    {}", reason);
                }
            }
            Logging::println("[FAIL] {}: {}/{} entries mismatched", ZydisMnemonicGetString(mnemonic), failures, entries);
        }
    }

    Logging::println(
        "Validation done: {} entries checked, {} mismatched, {} files missing, {} files unreadable", totalEntries,
        totalFailures, filesMissing, filesUnreadable);

    Logging::endProgress();
}

static std::optional<Filter> buildFilter(
    const std::vector<std::string>& mnemonicNames, const std::vector<std::string>& isaNames,
    const std::vector<std::string>& categoryNames, const std::vector<std::string>& excludeNames)
{
    Filter filter;

    if (mnemonicNames.empty())
    {
        filter.mnemonics.set();
    }
    else
    {
        for (const auto& name : mnemonicNames)
        {
            const auto m = Utils::resolveMnemonic(name);
            if (!m)
            {
                Logging::println("Unknown mnemonic: {}", name);
                return std::nullopt;
            }
            filter.mnemonics.set(static_cast<std::size_t>(*m));
        }
    }

    if (isaNames.empty())
    {
        filter.isaExts.set();
    }
    else
    {
        for (const auto& name : isaNames)
        {
            const auto e = Utils::resolveIsaExt(name);
            if (!e)
            {
                Logging::println("Unknown ISA extension: {}", name);
                return std::nullopt;
            }
            filter.isaExts.set(static_cast<std::size_t>(*e));
        }
    }

    if (categoryNames.empty())
    {
        filter.categories.set();
    }
    else
    {
        for (const auto& name : categoryNames)
        {
            const auto c = Utils::resolveCategory(name);
            if (!c)
            {
                Logging::println("Unknown category: {}", name);
                return std::nullopt;
            }
            filter.categories.set(static_cast<std::size_t>(*c));
        }
    }

    for (const auto& name : excludeNames)
    {
        const auto m = Utils::resolveMnemonic(name);
        if (!m)
        {
            Logging::println("Unknown mnemonic (exclude): {}", name);
            return std::nullopt;
        }
        filter.mnemonics.reset(static_cast<std::size_t>(*m));
    }

    return filter;
}

namespace x86Tester
{
    int runGenerator(const GeneratorOptions& options)
    {
        setMaxThreads(options.maxThreads);

        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;

        const auto filter = buildFilter(options.mnemonicNames, options.isaNames, options.categoryNames, options.excludeNames);
        if (!filter)
            return EXIT_FAILURE;

        const auto finalList = Generator::buildMnemonicIndex(mode, *filter);

        if (options.showList)
        {
            for (const auto m : finalList)
                Logging::println("{}", ZydisMnemonicGetString(m));
            Logging::println("Total: {} mnemonics", finalList.size());
            return EXIT_SUCCESS;
        }

        const auto& cpu = Cpuid::getCpuInfo();
        auto outputPath = options.outputPath;
        outputPath /= fmt::format("{}_f{}m{}s{}", cpu.name, cpu.family, cpu.model, cpu.stepping);
        Logging::println("Output directory: {}", outputPath.string());

        Generator::setStopOnImpossible(options.stopOnImpossible);

        const auto generated = options.validateOnly ? finalList : generateTests(finalList, mode, outputPath, options.force);

        if (!options.skipValidation)
            validateTests(finalList, mode, outputPath, options.validateFull);

        Logging::stopTitleMonitor();

        return EXIT_SUCCESS;
    }
}
