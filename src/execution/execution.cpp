#include "x86Tester/execution.hpp"

namespace x86Tester::Execution
{
    namespace
    {
        struct ThreadContext
        {
            Context* ctx = nullptr;

            ~ThreadContext()
            {
                if (ctx != nullptr)
                    cleanup(ctx);
            }
        };

        thread_local ThreadContext t_context;
    }

    Context* acquireContext(ZydisMachineMode mode, std::span<const std::uint8_t> code)
    {
        if (t_context.ctx != nullptr)
        {
            if (reset(t_context.ctx, mode, code))
                return t_context.ctx;

            cleanup(t_context.ctx);
            t_context.ctx = nullptr;
        }

        t_context.ctx = prepare(mode, code);
        return t_context.ctx;
    }

    void releaseContext(Context* ctx, bool healthy)
    {
        if (ctx == nullptr)
            return;

        if (!healthy)
        {
            if (t_context.ctx == ctx)
                t_context.ctx = nullptr;

            cleanup(ctx);
        }
    }
}
