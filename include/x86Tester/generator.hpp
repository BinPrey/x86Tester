#pragma once

#include <Zydis/Zydis.h>
#include <bitset>
#include <cstdint>
#include <functional>
#include <optional>
#include <sfl/small_flat_map.hpp>
#include <sfl/small_vector.hpp>
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

        template<typename... TMnemonics> Filter addMnemonics(TMnemonics... mnemonic)
        {
            auto res = *this;
            (res.mnemonics.set(static_cast<size_t>(mnemonic)), ...);
            return res;
        }
    };

    InstructionEntries buildInstructions(
        ZydisMachineMode mode, const Filter& filter, bool buildInParallel, ProgressReportFn reporter = {});

    bool isSupportedCategory(ZydisInstructionCategory category);

    bool isSupportedIsaExt(ZydisISAExt isaExt);

    struct MnemonicInfo
    {
        bool encodable{};
        ZydisInstructionCategory category{};
        ZydisISAExt isaExt{};
    };

    std::vector<MnemonicInfo> buildMnemonicIndex(ZydisMachineMode mode);

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

    using RegTestData = sfl::small_vector<std::uint8_t, 8>;

    struct TestCaseEntry
    {
        sfl::small_flat_map<ZydisRegister, RegTestData, 2> inputRegs;
        std::optional<std::uint32_t> inputFlags;
        sfl::small_flat_map<ZydisRegister, RegTestData, 2> outputRegs;
        std::optional<std::uint32_t> outputFlags;
        std::optional<ExceptionType> exceptionType;

        bool operator==(const TestCaseEntry& other) const
        {
            return inputRegs == other.inputRegs && inputFlags == other.inputFlags && outputRegs == other.outputRegs
                && outputFlags == other.outputFlags && exceptionType == other.exceptionType;
        }

        bool operator<(const TestCaseEntry& other) const
        {
            return std::tie(inputRegs, inputFlags, outputRegs, outputFlags, exceptionType)
                < std::tie(other.inputRegs, other.inputFlags, other.outputRegs, other.outputFlags, other.exceptionType);
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

} // namespace x86Tester::Generator