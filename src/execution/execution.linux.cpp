#include "x86Tester/execution.hpp"

#include <Zydis/Disassembler.h>
#include <array>
#include <cassert>
#include <cstring>
#include <span>
#include <vector>

#include <cpuid.h>
#include <elf.h>
#include <sched.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NT_X86_XSTATE
#    define NT_X86_XSTATE 0x202
#endif

namespace x86Tester::Execution
{
    static constexpr std::size_t kPageSize = 4096;

    struct Context
    {
        pid_t pid{ -1 };
        std::uintptr_t codeBase{};
        std::uintptr_t codeAddr{};
        std::uintptr_t breakAddr{};
        std::size_t codeSize{};
        user_regs_struct regs{};
        std::vector<std::uint8_t> xstate;
        user_fpregs_struct* fpregs{};
        std::size_t xstateSize{};
        std::size_t ymmOff{};
        std::size_t zmmHiOff{};
        std::size_t hi16Off{};
        std::size_t maskOff{};
        std::uint64_t xstateBv{};
        ExecutionStatus status{ ExecutionStatus::Idle };
        bool useFpRegs{ true };
    };

    [[noreturn]] static void childEntry()
    {
        syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);

        long page = 0;
        __asm__ volatile(
            "movq $9, %%rax\n\t"
            "movq $0x4000000, %%rdi\n\t"
            "movq %1, %%rsi\n\t"
            "movq $7, %%rdx\n\t"
            "movq $0x32, %%r10\n\t"
            "movq $-1, %%r8\n\t"
            "xorq %%r9, %%r9\n\t"
            "syscall\n\t"
            "int3\n\t"
            : "=a"(page)
            : "r"(static_cast<long>(kPageSize))
            : "rdi", "rsi", "rdx", "r10", "r8", "r9", "rcx", "r11", "memory");

        for (;;)
            syscall(SYS_exit, 0);
    }

    static bool spawnProcess(Context* ctx)
    {
        const pid_t pid = fork();
        if (pid < 0)
            return false;
        if (pid == 0)
            childEntry();

        ctx->pid = pid;

        int status = 0;
        if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status))
            return false;

        ptrace(PTRACE_SETOPTIONS, pid, 0, reinterpret_cast<void*>(PTRACE_O_EXITKILL));

        if (ptrace(PTRACE_GETREGS, pid, 0, &ctx->regs) != 0)
            return false;

        const auto page = static_cast<std::int64_t>(ctx->regs.rax);
        if (page <= 0)
            return false;

        ctx->codeBase = static_cast<std::uintptr_t>(page);
        return true;
    }

    static bool setupCode(Context* ctx, std::span<const std::uint8_t> code)
    {
        std::vector<std::uint8_t> buffer;
        buffer.reserve(code.size() + 2 + 8);
        buffer.push_back(0xCC);
        buffer.insert(buffer.end(), code.begin(), code.end());
        buffer.push_back(0xCC);
        while (buffer.size() % sizeof(long) != 0)
            buffer.push_back(0xCC);

        ctx->codeAddr = ctx->codeBase + 1;
        ctx->breakAddr = ctx->codeBase + 1 + code.size();
        ctx->codeSize = code.size() + 2;

        for (std::size_t i = 0; i < buffer.size(); i += sizeof(long))
        {
            long word = 0;
            std::memcpy(&word, buffer.data() + i, sizeof(long));
            if (ptrace(PTRACE_POKETEXT, ctx->pid, reinterpret_cast<void*>(ctx->codeBase + i),
                    reinterpret_cast<void*>(word))
                != 0)
                return false;
        }

        return true;
    }

    static bool setupXState(Context* ctx)
    {
        unsigned a = 0, b = 0, c = 0, d = 0;
        __cpuid_count(0x0D, 0, a, b, c, d);
        ctx->xstateBv = static_cast<std::uint64_t>(a) | (static_cast<std::uint64_t>(d) << 32);
        ctx->xstateSize = (c != 0) ? c : 512;

        __cpuid_count(0x0D, 2, a, b, c, d);
        ctx->ymmOff = b;
        __cpuid_count(0x0D, 5, a, b, c, d);
        ctx->maskOff = b;
        __cpuid_count(0x0D, 6, a, b, c, d);
        ctx->zmmHiOff = b;
        __cpuid_count(0x0D, 7, a, b, c, d);
        ctx->hi16Off = b;

        ctx->xstate.assign(ctx->xstateSize, 0);
        ctx->fpregs = reinterpret_cast<user_fpregs_struct*>(ctx->xstate.data());

        iovec iov{ ctx->xstate.data(), ctx->xstate.size() };
        if (ptrace(PTRACE_GETREGSET, ctx->pid, reinterpret_cast<void*>(static_cast<std::uintptr_t>(NT_X86_XSTATE)), &iov) != 0)
            return false;

        std::memcpy(ctx->xstate.data() + 512, &ctx->xstateBv, sizeof(ctx->xstateBv));
        return true;
    }

    static bool setupContext(Context* ctx)
    {
        if (ptrace(PTRACE_GETREGS, ctx->pid, 0, &ctx->regs) != 0)
            return false;
        if (!setupXState(ctx))
            return false;

        ctx->regs.rax = 0;
        ctx->regs.rcx = 0;
        ctx->regs.rdx = 0;
        ctx->regs.rbx = 0;
        ctx->regs.rsp = 0;
        ctx->regs.rbp = 0;
        ctx->regs.rsi = 0;
        ctx->regs.rdi = 0;
        ctx->regs.r8 = 0;
        ctx->regs.r9 = 0;
        ctx->regs.r10 = 0;
        ctx->regs.r11 = 0;
        ctx->regs.r12 = 0;
        ctx->regs.r13 = 0;
        ctx->regs.r14 = 0;
        ctx->regs.r15 = 0;
        ctx->regs.rip = ctx->codeAddr;

        return true;
    }

    static bool computeUseFpRegs(ZydisMachineMode mode, std::span<const std::uint8_t> code)
    {
        ZydisDisassembledInstruction instr;
        if (!ZYAN_SUCCESS(ZydisDisassembleIntel(mode, 0, code.data(), code.size(), &instr)))
            return true;

        for (std::size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type != ZYDIS_OPERAND_TYPE_REGISTER)
                continue;

            switch (ZydisRegisterGetClass(op.reg.value))
            {
                case ZYDIS_REGCLASS_GPR8:
                case ZYDIS_REGCLASS_GPR16:
                case ZYDIS_REGCLASS_GPR32:
                case ZYDIS_REGCLASS_GPR64:
                case ZYDIS_REGCLASS_FLAGS:
                case ZYDIS_REGCLASS_IP:
                    break;
                default:
                    return true;
            }
        }

        return false;
    }

    Context* prepare(ZydisMachineMode mode, std::span<const std::uint8_t> code)
    {
        auto ctx = new Context{};

        if (!spawnProcess(ctx) || !setupCode(ctx, code) || !setupContext(ctx))
        {
            cleanup(ctx);
            return nullptr;
        }

        ctx->useFpRegs = computeUseFpRegs(mode, code);

        return ctx;
    }

    std::span<std::uint8_t> getContextReg(Context* ctx, ZydisRegister reg)
    {
        auto bytes = [](auto& dst, std::size_t n) {
            return std::span(reinterpret_cast<std::uint8_t*>(&dst), n);
        };

        switch (reg)
        {
            case ZYDIS_REGISTER_RAX:
                return bytes(ctx->regs.rax, 8);
            case ZYDIS_REGISTER_RCX:
                return bytes(ctx->regs.rcx, 8);
            case ZYDIS_REGISTER_RDX:
                return bytes(ctx->regs.rdx, 8);
            case ZYDIS_REGISTER_RBX:
                return bytes(ctx->regs.rbx, 8);
            case ZYDIS_REGISTER_RSP:
                return bytes(ctx->regs.rsp, 8);
            case ZYDIS_REGISTER_RBP:
                return bytes(ctx->regs.rbp, 8);
            case ZYDIS_REGISTER_RSI:
                return bytes(ctx->regs.rsi, 8);
            case ZYDIS_REGISTER_RDI:
                return bytes(ctx->regs.rdi, 8);
            case ZYDIS_REGISTER_R8:
                return bytes(ctx->regs.r8, 8);
            case ZYDIS_REGISTER_R9:
                return bytes(ctx->regs.r9, 8);
            case ZYDIS_REGISTER_R10:
                return bytes(ctx->regs.r10, 8);
            case ZYDIS_REGISTER_R11:
                return bytes(ctx->regs.r11, 8);
            case ZYDIS_REGISTER_R12:
                return bytes(ctx->regs.r12, 8);
            case ZYDIS_REGISTER_R13:
                return bytes(ctx->regs.r13, 8);
            case ZYDIS_REGISTER_R14:
                return bytes(ctx->regs.r14, 8);
            case ZYDIS_REGISTER_R15:
                return bytes(ctx->regs.r15, 8);
            case ZYDIS_REGISTER_RIP:
                return bytes(ctx->regs.rip, 8);
            case ZYDIS_REGISTER_RFLAGS:
                [[fallthrough]];
            case ZYDIS_REGISTER_EFLAGS:
                return bytes(ctx->regs.eflags, 4);
            case ZYDIS_REGISTER_XMM0:
                return bytes(ctx->fpregs->xmm_space[0], 16);
            case ZYDIS_REGISTER_XMM1:
                return bytes(ctx->fpregs->xmm_space[4], 16);
            case ZYDIS_REGISTER_XMM2:
                return bytes(ctx->fpregs->xmm_space[8], 16);
            case ZYDIS_REGISTER_XMM3:
                return bytes(ctx->fpregs->xmm_space[12], 16);
            case ZYDIS_REGISTER_XMM4:
                return bytes(ctx->fpregs->xmm_space[16], 16);
            case ZYDIS_REGISTER_XMM5:
                return bytes(ctx->fpregs->xmm_space[20], 16);
            case ZYDIS_REGISTER_XMM6:
                return bytes(ctx->fpregs->xmm_space[24], 16);
            case ZYDIS_REGISTER_XMM7:
                return bytes(ctx->fpregs->xmm_space[28], 16);
            case ZYDIS_REGISTER_XMM8:
                return bytes(ctx->fpregs->xmm_space[32], 16);
            case ZYDIS_REGISTER_XMM9:
                return bytes(ctx->fpregs->xmm_space[36], 16);
            case ZYDIS_REGISTER_XMM10:
                return bytes(ctx->fpregs->xmm_space[40], 16);
            case ZYDIS_REGISTER_XMM11:
                return bytes(ctx->fpregs->xmm_space[44], 16);
            case ZYDIS_REGISTER_XMM12:
                return bytes(ctx->fpregs->xmm_space[48], 16);
            case ZYDIS_REGISTER_XMM13:
                return bytes(ctx->fpregs->xmm_space[52], 16);
            case ZYDIS_REGISTER_XMM14:
                return bytes(ctx->fpregs->xmm_space[56], 16);
            case ZYDIS_REGISTER_XMM15:
                return bytes(ctx->fpregs->xmm_space[60], 16);
            case ZYDIS_REGISTER_ST0:
                return bytes(ctx->fpregs->st_space[0], 16);
            case ZYDIS_REGISTER_ST1:
                return bytes(ctx->fpregs->st_space[4], 16);
            case ZYDIS_REGISTER_ST2:
                return bytes(ctx->fpregs->st_space[8], 16);
            case ZYDIS_REGISTER_ST3:
                return bytes(ctx->fpregs->st_space[12], 16);
            case ZYDIS_REGISTER_ST4:
                return bytes(ctx->fpregs->st_space[16], 16);
            case ZYDIS_REGISTER_ST5:
                return bytes(ctx->fpregs->st_space[20], 16);
            case ZYDIS_REGISTER_ST6:
                return bytes(ctx->fpregs->st_space[24], 16);
            case ZYDIS_REGISTER_ST7:
                return bytes(ctx->fpregs->st_space[28], 16);
            case ZYDIS_REGISTER_X87STATUS:
                return bytes(ctx->fpregs->swd, 2);
            case ZYDIS_REGISTER_X87CONTROL:
                return bytes(ctx->fpregs->cwd, 2);
            case ZYDIS_REGISTER_X87TAG:
                return bytes(ctx->fpregs->ftw, 2);
            case ZYDIS_REGISTER_MXCSR:
                return bytes(ctx->fpregs->mxcsr, 4);
        }

        assert(false);
        return {};
    }

    static bool isWideOrMaskReg(ZydisRegister reg)
    {
        return (reg >= ZYDIS_REGISTER_XMM16 && reg <= ZYDIS_REGISTER_XMM31)
            || (reg >= ZYDIS_REGISTER_YMM0 && reg <= ZYDIS_REGISTER_YMM31)
            || (reg >= ZYDIS_REGISTER_ZMM0 && reg <= ZYDIS_REGISTER_ZMM31)
            || (reg >= ZYDIS_REGISTER_K0 && reg <= ZYDIS_REGISTER_K7);
    }

    static void wideRegLayout(ZydisRegister reg, unsigned& idx, unsigned& width, bool& isMask)
    {
        isMask = false;
        if (reg >= ZYDIS_REGISTER_K0 && reg <= ZYDIS_REGISTER_K7)
        {
            idx = static_cast<unsigned>(reg - ZYDIS_REGISTER_K0);
            width = 8;
            isMask = true;
        }
        else if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM31)
        {
            idx = static_cast<unsigned>(reg - ZYDIS_REGISTER_XMM0);
            width = 16;
        }
        else if (reg >= ZYDIS_REGISTER_YMM0 && reg <= ZYDIS_REGISTER_YMM31)
        {
            idx = static_cast<unsigned>(reg - ZYDIS_REGISTER_YMM0);
            width = 32;
        }
        else
        {
            idx = static_cast<unsigned>(reg - ZYDIS_REGISTER_ZMM0);
            width = 64;
        }
    }

    static std::uint8_t* xstateComp(Context* ctx, std::size_t off)
    {
        return off != 0 ? ctx->xstate.data() + off : nullptr;
    }

    bool setRegBytes(Context* ctx, ZydisRegister reg, std::span<const std::uint8_t> data)
    {
        if (isWideOrMaskReg(reg))
        {
            unsigned idx = 0, width = 0;
            bool isMask = false;
            wideRegLayout(reg, idx, width, isMask);
            const std::size_t n = data.size();

            if (isMask)
            {
                if (auto* k = xstateComp(ctx, ctx->maskOff))
                    std::memcpy(k + idx * 8, data.data(), std::min<std::size_t>(8, n));
                return true;
            }

            if (idx < 16)
            {
                std::memcpy(&ctx->fpregs->xmm_space[idx * 4], data.data(), std::min<std::size_t>(16, n));
                if (n > 16)
                    if (auto* avx = xstateComp(ctx, ctx->ymmOff))
                        std::memcpy(avx + idx * 16, data.data() + 16, std::min<std::size_t>(16, n - 16));
                if (n > 32)
                    if (auto* zh = xstateComp(ctx, ctx->zmmHiOff))
                        std::memcpy(zh + idx * 32, data.data() + 32, std::min<std::size_t>(32, n - 32));
            }
            else
            {
                if (auto* hi = xstateComp(ctx, ctx->hi16Off))
                    std::memcpy(hi + (idx - 16) * 64, data.data(), std::min<std::size_t>(width, n));
            }
            return true;
        }

        auto regData = getContextReg(ctx, reg);
        if (data.size() > regData.size())
        {
            assert(false);
            return false;
        }

        std::copy(data.begin(), data.end(), regData.begin());
        return true;
    }

    sfl::small_vector<std::uint8_t, 16> getRegBytes(Context* ctx, ZydisRegister reg)
    {
        if (isWideOrMaskReg(reg))
        {
            unsigned idx = 0, width = 0;
            bool isMask = false;
            wideRegLayout(reg, idx, width, isMask);

            sfl::small_vector<std::uint8_t, 16> out(width, std::uint8_t{ 0 });

            if (isMask)
            {
                if (auto* k = xstateComp(ctx, ctx->maskOff))
                    std::memcpy(out.data(), k + idx * 8, 8);
                return out;
            }

            if (idx < 16)
            {
                std::memcpy(out.data(), &ctx->fpregs->xmm_space[idx * 4], 16);
                if (width >= 32)
                    if (auto* avx = xstateComp(ctx, ctx->ymmOff))
                        std::memcpy(out.data() + 16, avx + idx * 16, 16);
                if (width >= 64)
                    if (auto* zh = xstateComp(ctx, ctx->zmmHiOff))
                        std::memcpy(out.data() + 32, zh + idx * 32, 32);
            }
            else
            {
                if (auto* hi = xstateComp(ctx, ctx->hi16Off))
                    std::memcpy(out.data(), hi + (idx - 16) * 64, width);
            }
            return out;
        }

        const auto s = getContextReg(ctx, reg);
        return sfl::small_vector<std::uint8_t, 16>(s.begin(), s.end());
    }

    bool execute(Context* ctx)
    {
        ctx->status = ExecutionStatus::Idle;
        ctx->regs.rip = ctx->codeAddr;

        if (ptrace(PTRACE_SETREGS, ctx->pid, 0, &ctx->regs) != 0)
            return false;

        if (ctx->useFpRegs)
        {
            ctx->fpregs->ftw = 0xFF;
            ctx->fpregs->swd &= 0xC7FF;
            std::memcpy(ctx->xstate.data() + 512, &ctx->xstateBv, sizeof(ctx->xstateBv));
            iovec iov{ ctx->xstate.data(), ctx->xstate.size() };
            if (ptrace(PTRACE_SETREGSET, ctx->pid, reinterpret_cast<void*>(static_cast<std::uintptr_t>(NT_X86_XSTATE)), &iov) != 0)
                return false;
        }

        if (ptrace(PTRACE_CONT, ctx->pid, 0, 0) != 0)
            return false;

        int status = 0;
        if (waitpid(ctx->pid, &status, 0) != ctx->pid || !WIFSTOPPED(status))
            return false;

        if (ptrace(PTRACE_GETREGS, ctx->pid, 0, &ctx->regs) != 0)
            return false;

        switch (WSTOPSIG(status))
        {
            case SIGTRAP:
                ctx->status = (ctx->regs.rip == ctx->breakAddr + 1) ? ExecutionStatus::Success
                                                                    : ExecutionStatus::Idle;
                break;
            case SIGILL:
                ctx->status = ExecutionStatus::IllegalInstruction;
                break;
            case SIGFPE:
            {
                siginfo_t info{};
                ptrace(PTRACE_GETSIGINFO, ctx->pid, 0, &info);
                ctx->status = info.si_code == FPE_INTOVF ? ExecutionStatus::ExceptionIntOverflow
                                                         : ExecutionStatus::ExceptionIntDivideError;
                break;
            }
            default:
                ctx->status = ExecutionStatus::Idle;
                break;
        }

        if (ctx->useFpRegs)
        {
            iovec iov{ ctx->xstate.data(), ctx->xstate.size() };
            ptrace(PTRACE_GETREGSET, ctx->pid, reinterpret_cast<void*>(static_cast<std::uintptr_t>(NT_X86_XSTATE)), &iov);
        }

        return true;
    }

    void pinThread(Context* ctx, unsigned core)
    {
        if (ctx == nullptr || ctx->pid <= 0)
            return;
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(core, &set);
        sched_setaffinity(ctx->pid, sizeof(set), &set);
    }

    void cleanup(Context* ctx)
    {
        if (ctx == nullptr)
            return;

        if (ctx->pid > 0)
        {
            kill(ctx->pid, SIGKILL);
            int status = 0;
            waitpid(ctx->pid, &status, 0);
        }

        delete ctx;
    }

    std::uint64_t getBaseAddress(Context* ctx)
    {
        return ctx->codeBase;
    }

    std::uint64_t getCodeAddress(Context* ctx)
    {
        return ctx->codeAddr;
    }

    ExecutionStatus getExecutionStatus(Context* ctx)
    {
        return ctx->status;
    }

} // namespace x86Tester::Execution
