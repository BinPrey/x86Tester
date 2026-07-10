#pragma once

#include <Zydis/Defines.h>
#include <Zydis/Register.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sfl/small_vector.hpp>
#include <span>

namespace x86Tester::Execution
{
    struct Context;

    enum class ExecutionStatus
    {
        Idle,
        Success,
        ExceptionIntDivideError,
        ExceptionIntOverflow,
        IllegalInstruction,
    };

    Context* prepare(ZydisMachineMode mode, std::span<const std::uint8_t> code);

    std::uint64_t getBaseAddress(Context* ctx);

    std::uint64_t getCodeAddress(Context* ctx);

    bool setRegBytes(Context* ctx, ZydisRegister reg, std::span<const std::uint8_t> data);

    sfl::small_vector<std::uint8_t, 16> getRegBytes(Context* ctx, ZydisRegister reg);

    bool execute(Context* ctx);

    void pinThread(Context* ctx, unsigned core);

    void cleanup(Context* ctx);

    ExecutionStatus getExecutionStatus(Context* ctx);

    class ScopedContext
    {
        Context* ctx;

    public:
        ScopedContext(ZydisMachineMode mode, std::span<const std::uint8_t> code)
            : ctx(prepare(mode, code))
        {
        }

        ~ScopedContext()
        {
            cleanup(ctx);
        }

        Context* get() const
        {
            return ctx;
        }

        operator bool() const
        {
            return ctx != nullptr;
        }

        bool execute()
        {
            return x86Tester::Execution::execute(ctx);
        }

        void pinThread(unsigned core)
        {
            x86Tester::Execution::pinThread(ctx, core);
        }

        uint64_t getBaseAddress() const
        {
            return x86Tester::Execution::getBaseAddress(ctx);
        }

        uint64_t getCodeAddress() const
        {
            return x86Tester::Execution::getCodeAddress(ctx);
        }

        bool setRegBytes(ZydisRegister reg, std::span<const std::uint8_t> data)
        {
            return x86Tester::Execution::setRegBytes(ctx, reg, data);
        }

        template<typename T> bool setRegValue(ZydisRegister reg, T data)
        {
            return x86Tester::Execution::setRegBytes(
                ctx, reg, std::span(reinterpret_cast<const std::uint8_t*>(&data), sizeof(T)));
        }

        sfl::small_vector<std::uint8_t, 16> getRegBytes(ZydisRegister reg) const
        {
            return x86Tester::Execution::getRegBytes(ctx, reg);
        }

        template<typename T> T getRegValue(ZydisRegister reg) const
        {
            T val{};
            const auto data = x86Tester::Execution::getRegBytes(ctx, reg);
            std::memcpy(&val, data.data(), std::min(data.size(), sizeof(T)));
            return val;
        }

        ExecutionStatus getExecutionStatus() const
        {
            return x86Tester::Execution::getExecutionStatus(ctx);
        }
    };

} // namespace x86Tester::Execution