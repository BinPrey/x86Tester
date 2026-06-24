#include <Zydis/Disassembler.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <random>
#include <ranges>
#include <set>
#include <sfl/small_flat_map.hpp>
#include <sfl/small_flat_set.hpp>
#include <sfl/small_vector.hpp>
#include <sfl/static_vector.hpp>
#include <sfl/vector.hpp>
#include <x86Tester/execution.hpp>
#include <x86Tester/generator.hpp>
#include <x86Tester/inputgenerator.hpp>
#include <x86Tester/logging.hpp>

namespace x86Tester::tests
{
    static constexpr auto kCCBytes = std::to_array<std::uint8_t>(
        { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC });

    TEST(ExecutionTest, add_al_al)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 2>{
            0x00,
            0xC0,
        };

        auto ctx = Execution::ScopedContext(mode, instrBytes);
        ASSERT_TRUE(ctx);

        constexpr auto raxValue = std::to_array<std::uint8_t>({ 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC });

        ctx.setRegBytes(ZYDIS_REGISTER_RAX, raxValue);

        ASSERT_TRUE(ctx.execute());

        const auto raxOutput = ctx.getRegBytes(ZYDIS_REGISTER_RAX);

        const auto expectedRaxValue = std::to_array<std::uint8_t>({ 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC });

        ASSERT_TRUE(std::ranges::equal(raxOutput, expectedRaxValue));

        const auto flagsOutput = ctx.getRegBytes(ZYDIS_REGISTER_EFLAGS);
        const auto expectedFlags = std::to_array<std::uint8_t>({ 0x46, 0x02, 0x00, 0x00 });

        ASSERT_TRUE(std::ranges::equal(flagsOutput, expectedFlags));
    }

    TEST(ExecutionTest, cvtdq2pd_xmm3_xmm0)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 4>{ 0xF3, 0x0F, 0xE6, 0xD8 };

        auto ctx = Execution::ScopedContext(mode, instrBytes);
        ASSERT_TRUE(ctx);

        constexpr auto xmm0Value = std::to_array<std::uint8_t>(
            { 0xFF, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

        ctx.setRegBytes(ZYDIS_REGISTER_XMM0, xmm0Value);
        ctx.setRegBytes(ZYDIS_REGISTER_XMM3, kCCBytes);

        ASSERT_TRUE(ctx.execute());

        const auto xmm3Value = ctx.getRegBytes(ZYDIS_REGISTER_XMM3);

        const auto expectedXmm3Value = std::to_array<std::uint8_t>(
            { 0x00, 0x00, 0x00, 0x40, 0xC0, 0xFF, 0x5F, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0xBF });

        ASSERT_TRUE(std::ranges::equal(xmm3Value, expectedXmm3Value));
    }

    TEST(ExecutionTest, idiv_ah)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 2>{
            0xF6,
            0xFC,
        };

        auto ctx = Execution::ScopedContext(mode, instrBytes);
        ASSERT_TRUE(ctx);

        constexpr auto raxValue = std::to_array<std::uint8_t>({ 0x00, 0x08, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC });

        ctx.setRegBytes(ZYDIS_REGISTER_RAX, raxValue);

        ASSERT_TRUE(ctx.execute());

        const auto raxOutput = ctx.getRegBytes(ZYDIS_REGISTER_RAX);

        ASSERT_EQ(std::ranges::equal(raxOutput, raxValue), true);

        ASSERT_EQ(ctx.getExecutionStatus(), Execution::ExecutionStatus::ExceptionIntOverflow);
    }

    TEST(ExecutionTest, div_cl_zero_reports_divide_error)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 2>{ 0xF6, 0xF1 }; // div cl

        auto ctx = Execution::ScopedContext(mode, instrBytes);
        ASSERT_TRUE(ctx);

        ctx.setRegValue(ZYDIS_REGISTER_RAX, std::uint64_t{ 0x0100 });
        ctx.setRegValue(ZYDIS_REGISTER_RCX, std::uint64_t{ 0 });

        ASSERT_TRUE(ctx.execute());

        ASSERT_EQ(ctx.getExecutionStatus(), Execution::ExecutionStatus::ExceptionIntDivideError);
    }

    TEST(ExecutionTest, status_not_stale_after_fault)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 2>{ 0x8B, 0x01 }; // mov eax, [rcx]

        auto ctx = Execution::ScopedContext(mode, instrBytes);
        ASSERT_TRUE(ctx);

        // Point rcx at the readable code page: succeeds.
        ctx.setRegValue(ZYDIS_REGISTER_RCX, ctx.getCodeAddress());
        ASSERT_TRUE(ctx.execute());
        ASSERT_EQ(ctx.getExecutionStatus(), Execution::ExecutionStatus::Success);

        // Point rcx at an unmapped address: faults, status must not remain Success.
        ctx.setRegValue(ZYDIS_REGISTER_RCX, std::uint64_t{ 0 });
        ASSERT_TRUE(ctx.execute());
        ASSERT_NE(ctx.getExecutionStatus(), Execution::ExecutionStatus::Success);
    }

    TEST(GeneratorTest, movzx_eax_al_high_bits_zero)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 3>{ 0x0F, 0xB6, 0xC0 };

        const auto group = Generator::generateInstructionTestData(mode, instrBytes);

        ASSERT_FALSE(group.entries.empty());
        ASSERT_FALSE(group.illegalInstruction);

        for (const auto& entry : group.entries)
        {
            const auto it = entry.outputRegs.find(ZYDIS_REGISTER_RAX);
            ASSERT_NE(it, entry.outputRegs.end());

            const auto& bytes = it->second;
            ASSERT_GE(bytes.size(), 8u);
            for (std::size_t i = 1; i < bytes.size(); ++i)
                ASSERT_EQ(bytes[i], 0u) << "byte " << i << " must be zero for movzx eax, al";
        }
    }

    TEST(GeneratorTest, add_eax_ebx_covers_both_bit_values)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 2>{ 0x01, 0xD8 };

        const auto group = Generator::generateInstructionTestData(mode, instrBytes);

        ASSERT_FALSE(group.entries.empty());
        ASSERT_FALSE(group.illegalInstruction);

        std::uint32_t seenZero = 0;
        std::uint32_t seenOne = 0;
        for (const auto& entry : group.entries)
        {
            const auto it = entry.outputRegs.find(ZYDIS_REGISTER_RAX);
            if (it == entry.outputRegs.end())
                continue;

            std::uint32_t eax = 0;
            std::memcpy(&eax, it->second.data(), 4);
            seenOne |= eax;
            seenZero |= ~eax;
        }

        ASSERT_EQ(seenZero, 0xFFFFFFFFu) << "every bit of eax must be observed as 0 at least once";
        ASSERT_EQ(seenOne, 0xFFFFFFFFu) << "every bit of eax must be observed as 1 at least once";
    }

    TEST(GeneratorTest, blsmsk_eax_ebx_bit0_always_one)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 5>{ 0xC4, 0xE2, 0x78, 0xF3, 0xD3 };

        const auto group = Generator::generateInstructionTestData(mode, instrBytes);

        ASSERT_FALSE(group.entries.empty());
        ASSERT_FALSE(group.illegalInstruction);

        for (const auto& entry : group.entries)
        {
            const auto it = entry.outputRegs.find(ZYDIS_REGISTER_RAX);
            ASSERT_NE(it, entry.outputRegs.end());
            ASSERT_EQ(it->second[0] & 0x01, 0x01) << "blsmsk result bit 0 must always be set";
        }
    }

    TEST(GeneratorTest, blsr_eax_ebx_bit0_always_zero)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 5>{ 0xC4, 0xE2, 0x78, 0xF3, 0xCB };

        const auto group = Generator::generateInstructionTestData(mode, instrBytes);

        ASSERT_FALSE(group.entries.empty());
        ASSERT_FALSE(group.illegalInstruction);

        for (const auto& entry : group.entries)
        {
            const auto it = entry.outputRegs.find(ZYDIS_REGISTER_RAX);
            ASSERT_NE(it, entry.outputRegs.end());
            ASSERT_EQ(it->second[0] & 0x01, 0x00) << "blsr result bit 0 must always be clear";
        }
    }

    TEST(GeneratorTest, lea_scaled_with_disp_low_bits_known)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        // lea eax, [rax*2 + 1]  ->  result = 2*rax + 1, so bit 0 is always 1.
        const auto instrBytes = std::array<std::uint8_t, 7>{ 0x8D, 0x04, 0x45, 0x01, 0x00, 0x00, 0x00 };

        const auto group = Generator::generateInstructionTestData(mode, instrBytes);

        ASSERT_FALSE(group.entries.empty());
        ASSERT_FALSE(group.illegalInstruction);

        for (const auto& entry : group.entries)
        {
            const auto it = entry.outputRegs.find(ZYDIS_REGISTER_RAX);
            ASSERT_NE(it, entry.outputRegs.end());
            ASSERT_EQ(it->second[0] & 0x01, 0x01) << "lea [rax*2+1] result bit 0 must always be set";
        }
    }

    TEST(GeneratorTest, andn_same_source_is_always_zero)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 5>{ 0xC4, 0x42, 0x18, 0xF2, 0xCC }; // andn r9d, r12d, r12d

        const auto group = Generator::generateInstructionTestData(mode, instrBytes);

        ASSERT_FALSE(group.entries.empty());
        ASSERT_FALSE(group.illegalInstruction);

        for (const auto& entry : group.entries)
        {
            const auto it = entry.outputRegs.find(ZYDIS_REGISTER_R9);
            ASSERT_NE(it, entry.outputRegs.end());
            for (const auto byte : it->second)
                ASSERT_EQ(byte, 0u) << "andn r9d, r12d, r12d must produce all zeros";
        }
    }

    TEST(GeneratorTest, bsf_result_high_bits_zero)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 3>{ 0x0F, 0xBC, 0xC0 }; // bsf eax, eax

        const auto group = Generator::generateInstructionTestData(mode, instrBytes);

        ASSERT_FALSE(group.entries.empty());
        ASSERT_FALSE(group.illegalInstruction);

        for (const auto& entry : group.entries)
        {
            const auto it = entry.outputRegs.find(ZYDIS_REGISTER_RAX);
            ASSERT_NE(it, entry.outputRegs.end());

            std::uint32_t eax = 0;
            std::memcpy(&eax, it->second.data(), 4);
            ASSERT_LE(eax, 31u) << "bsf result is a bit index, must be <= 31";
        }
    }

    TEST(GeneratorTest, andnps_same_source_is_always_zero)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 4>{ 0x45, 0x0F, 0x55, 0xC9 }; // andnps xmm9, xmm9

        const auto group = Generator::generateInstructionTestData(mode, instrBytes);

        ASSERT_FALSE(group.entries.empty());
        ASSERT_FALSE(group.illegalInstruction);

        for (const auto& entry : group.entries)
        {
            const auto it = entry.outputRegs.find(ZYDIS_REGISTER_XMM9);
            ASSERT_NE(it, entry.outputRegs.end());
            for (const auto byte : it->second)
                ASSERT_EQ(byte, 0u) << "andnps xmm9, xmm9 must produce all zeros";
        }
    }

    TEST(GeneratorTest, cmpsd_self_lt_low_lane_zero)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 5>{ 0xF2, 0x0F, 0xC2, 0xD2, 0x01 }; // cmpsd xmm2, xmm2, 1

        const auto group = Generator::generateInstructionTestData(mode, instrBytes);

        ASSERT_FALSE(group.entries.empty());
        ASSERT_FALSE(group.illegalInstruction);

        for (const auto& entry : group.entries)
        {
            const auto it = entry.outputRegs.find(ZYDIS_REGISTER_XMM2);
            ASSERT_NE(it, entry.outputRegs.end());
            ASSERT_GE(it->second.size(), 8u);
            for (std::size_t i = 0; i < 8; ++i)
                ASSERT_EQ(it->second[i], 0u) << "cmpsd xmm2, xmm2, LT low lane must be zero";
        }
    }

    TEST(GeneratorTest, implicit_memory_instructions_are_skipped)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;

        // cmpsb (implicit [rsi]/[rdi])
        const auto cmpsb = Generator::generateInstructionTestData(mode, std::array<std::uint8_t, 1>{ 0xA6 });
        ASSERT_TRUE(cmpsb.entries.empty());

        // push rax (implicit [rsp])
        const auto push = Generator::generateInstructionTestData(mode, std::array<std::uint8_t, 1>{ 0x50 });
        ASSERT_TRUE(push.entries.empty());
    }

    TEST(GeneratorTest, cmppd_self_lt_is_always_zero)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        const auto instrBytes = std::array<std::uint8_t, 5>{ 0x66, 0x0F, 0xC2, 0xE4, 0x01 }; // cmppd xmm4, xmm4, 1

        const auto group = Generator::generateInstructionTestData(mode, instrBytes);

        ASSERT_FALSE(group.entries.empty());
        ASSERT_FALSE(group.illegalInstruction);

        for (const auto& entry : group.entries)
        {
            const auto it = entry.outputRegs.find(ZYDIS_REGISTER_XMM4);
            ASSERT_NE(it, entry.outputRegs.end());
            for (const auto byte : it->second)
                ASSERT_EQ(byte, 0u) << "cmppd xmm4, xmm4, LT must produce all zeros";
        }
    }

    TEST(GeneratorTest, privileged_instructions_are_skipped)
    {
        const auto mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;

        // hlt
        const auto hlt = Generator::generateInstructionTestData(mode, std::array<std::uint8_t, 1>{ 0xF4 });
        ASSERT_TRUE(hlt.entries.empty());

        // cli
        const auto cli = Generator::generateInstructionTestData(mode, std::array<std::uint8_t, 1>{ 0xFA });
        ASSERT_TRUE(cli.entries.empty());
    }

} // namespace x86Tester::tests
