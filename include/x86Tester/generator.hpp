#pragma once

#include <Zydis/Zydis.h>
#include <bitset>
#include <cstdint>
#include <functional>
#include <optional>
#include <sfl/small_flat_map.hpp>
#include <sfl/small_vector.hpp>
#include <sfl/static_vector.hpp>
#include <span>
#include <string>
#include <tuple>
#include <vector>
#include <x86Tester/shared.hpp>

namespace x86Tester::Generator
{
    using ProgressReportFn = std::function<void(size_t, size_t)>;

    struct Filter
    {
        std::bitset<ZYDIS_MNEMONIC_MAX_VALUE + 1> mnemonics{};
        std::bitset<ZYDIS_CATEGORY_MAX_VALUE + 1> categories{};
        std::bitset<ZYDIS_ISA_EXT_MAX_VALUE + 1> isaExts{};

        template<typename... TMnemonics> Filter addMnemonics(TMnemonics... mnemonic)
        {
            auto res = *this;
            (res.mnemonics.set(static_cast<size_t>(mnemonic)), ...);
            return res;
        }

        template<typename... TMnemonics> Filter excludeMnemonics(TMnemonics... mnemonic)
        {
            auto res = *this;
            (res.mnemonics.reset(static_cast<size_t>(mnemonic)), ...);
            return res;
        }

        template<typename... TCategories> Filter addCategories(TCategories... category)
        {
            auto res = *this;
            (res.categories.set(static_cast<size_t>(category)), ...);
            return res;
        }

        template<typename... TCategories> Filter excludeCategories(TCategories... category)
        {
            auto res = *this;
            (res.categories.reset(static_cast<size_t>(category)), ...);
            return res;
        }

        template<typename... TIsaExts> Filter addIsaExts(TIsaExts... isaExt)
        {
            auto res = *this;
            (res.isaExts.set(static_cast<size_t>(isaExt)), ...);
            return res;
        }

        template<typename... TIsaExts> Filter excludeIsaExts(TIsaExts... isaExt)
        {
            auto res = *this;
            (res.isaExts.reset(static_cast<size_t>(isaExt)), ...);
            return res;
        }

        bool passes(ZydisMnemonic mnemonic) const
        {
            // Must contain mnemonic.
            return mnemonics.test(static_cast<size_t>(mnemonic));
        }

        bool passes(ZydisInstructionCategory category) const
        {
            // Must contain category.
            return categories.test(static_cast<size_t>(category));
        }

        bool passes(ZydisISAExt isaExt) const
        {
            // Must contain isaExt.
            return isaExts.test(static_cast<size_t>(isaExt));
        }
    };

    InstructionEntries buildInstructions(
        ZydisMachineMode mode, ZydisMnemonic mnemonic, bool buildInParallel, ProgressReportFn reporter = {});

    std::vector<ZydisMnemonic> buildMnemonicIndex(ZydisMachineMode mode, const Filter& filter);

    sfl::static_vector<ZydisRegister, 7> getWrittenRegisters(const ZydisDisassembledInstruction& dis);

    sfl::static_vector<ZydisRegister, 7> getReadRegisters(const ZydisDisassembledInstruction& dis);

    void setStopOnImpossible(bool enable);
    bool stopRequested();
    std::string takeImpossibleReport();

    enum class ExceptionType
    {
        None,
        // #DE
        DivideError,
        IntegerOverflow,
    };

    using RegTestData = std::vector<std::uint8_t>;

    struct TestCaseEntry
    {
        sfl::small_flat_map<ZydisRegister, RegTestData, 2> inputRegs;
        sfl::small_flat_map<ZydisRegister, RegTestData, 2> outputRegs;
        sfl::small_flat_map<std::uint64_t, RegTestData, 1> inputMem;
        sfl::small_flat_map<std::uint64_t, RegTestData, 1> outputMem;
        std::optional<std::uint32_t> inputFlags;
        std::optional<std::uint32_t> outputFlags;
        std::optional<ExceptionType> exceptionType;

        bool operator==(const TestCaseEntry& other) const
        {
            return inputRegs == other.inputRegs && inputFlags == other.inputFlags && outputRegs == other.outputRegs
                && outputFlags == other.outputFlags && exceptionType == other.exceptionType
                && inputMem == other.inputMem && outputMem == other.outputMem;
        }

        bool operator<(const TestCaseEntry& other) const
        {
            return std::tie(inputRegs, inputFlags, outputRegs, outputFlags, exceptionType, inputMem, outputMem)
                < std::tie(
                    other.inputRegs, other.inputFlags, other.outputRegs, other.outputFlags, other.exceptionType,
                    other.inputMem, other.outputMem);
        }
    };

    struct InstrTestGroup
    {
        std::uint64_t address{};
        std::span<const uint8_t> instrData;
        std::vector<TestCaseEntry> entries;
        bool illegalInstruction{};
        size_t totalAttempts{};
    };

    InstrTestGroup generateInstructionTestData(ZydisMachineMode mode, std::span<const std::uint8_t> instrData);

    std::vector<InstrTestGroup> generateGroupedTestData(
        ZydisMachineMode mode, const InstructionEntries& instrs, ProgressReportFn reporter);

} // namespace x86Tester::Generator