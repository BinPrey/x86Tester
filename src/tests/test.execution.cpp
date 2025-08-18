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

} // namespace x86Tester::tests
