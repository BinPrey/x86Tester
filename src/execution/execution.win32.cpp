#include "x86Tester/execution.hpp"

#include <Zydis/Disassembler.h>
#include <Zydis/Encoder.h>
#include <array>
#include <cstring>
#include <fmt/format.h>
#include <intrin.h>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>
#include <x86Tester/logging.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#    define NOMINMAX
#endif
#include <Windows.h>

namespace x86Tester::Execution
{
    struct Context
    {
        STARTUPINFOW startupInfo{};
        PROCESS_INFORMATION processInfo{};
        HANDLE hThread{};
        std::uintptr_t codeBase{};
        std::uintptr_t codeAddr{};
        std::size_t codeSize{};
        std::uintptr_t breakAddr{};
        std::vector<std::uint8_t> contextStorage;
        CONTEXT* threadContext{};
        DWORD64 xstateMask{};
        DEBUG_EVENT dbgEvent{};
        ExecutionStatus status{};
        DWORD contextFlags{ CONTEXT_ALL };
    };

    enum class DebugStatus
    {
        Continue,
        SystemBreak,
        Exit,
        Faulted,
    };

    static void dumpDisassembly(Context* ctx, std::uintptr_t activeAddress)
    {
        // Decode the entire code region.
        for (size_t n = 0; n < ctx->codeSize;)
        {
            const std::uintptr_t addr = ctx->codeBase + n;

            std::uint8_t buffer[16]{};
            SIZE_T read;
            ReadProcessMemory(ctx->processInfo.hProcess, reinterpret_cast<void*>(addr), buffer, sizeof(buffer), &read);

            ZydisDisassembledInstruction instr;
            ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, addr, buffer, read, &instr);

            fmt::print("{}{:016X} ", addr == activeAddress ? ">" : " ", addr);

            n += instr.info.length;
        }
    }

    std::span<std::uint8_t> getContextReg(Context* ctx, ZydisRegister reg);

    static std::uint64_t readRegisterValue(Context* ctx, ZydisRegister reg, ZyanU16 sizeBits)
    {
        const auto root = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
        if (root == ZYDIS_REGISTER_NONE)
            return 0;

        const auto bytes = getContextReg(ctx, root);
        if (bytes.empty())
            return 0;

        std::size_t offset = 0;
        if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH)
            offset = 1;

        std::size_t nbytes = sizeBits / 8;
        if (nbytes == 0 || nbytes > 8)
            nbytes = 8;
        if (offset + nbytes > bytes.size())
            return 0;

        std::uint64_t value = 0;
        std::memcpy(&value, bytes.data() + offset, nbytes);
        return value;
    }

    static std::uint64_t computeMemoryAddress(Context* ctx, const ZydisDecodedOperand& op)
    {
        std::uint64_t addr = static_cast<std::uint64_t>(op.mem.disp.value);
        if (op.mem.base != ZYDIS_REGISTER_NONE && op.mem.base != ZYDIS_REGISTER_RIP && op.mem.base != ZYDIS_REGISTER_EIP)
            addr += readRegisterValue(ctx, op.mem.base, 64);
        if (op.mem.index != ZYDIS_REGISTER_NONE)
            addr += readRegisterValue(ctx, op.mem.index, 64) * op.mem.scale;
        return addr;
    }

    static ExecutionStatus classifyDivideError(Context* ctx, std::uintptr_t faultAddress)
    {
        std::uint8_t buffer[16]{};
        SIZE_T read = 0;
        if (!ReadProcessMemory(ctx->processInfo.hProcess, reinterpret_cast<void*>(faultAddress), buffer, sizeof(buffer), &read)
            || read == 0)
            return ExecutionStatus::ExceptionIntDivideError;

        ZydisDisassembledInstruction instr;
        if (!ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, faultAddress, buffer, read, &instr)))
            return ExecutionStatus::ExceptionIntDivideError;

        if (instr.info.mnemonic != ZYDIS_MNEMONIC_DIV && instr.info.mnemonic != ZYDIS_MNEMONIC_IDIV)
            return ExecutionStatus::ExceptionIntDivideError;

        if (instr.info.operand_count_visible == 0)
            return ExecutionStatus::ExceptionIntDivideError;

        const auto& divisor = instr.operands[0];

        std::uint64_t value = 0;
        bool haveValue = false;

        if (divisor.type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            value = readRegisterValue(ctx, divisor.reg.value, divisor.size);
            haveValue = true;
        }
        else if (divisor.type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            const auto addr = computeMemoryAddress(ctx, divisor);
            const std::size_t nbytes = divisor.size / 8;
            std::uint64_t mem = 0;
            SIZE_T r = 0;
            if (nbytes >= 1 && nbytes <= 8
                && ReadProcessMemory(ctx->processInfo.hProcess, reinterpret_cast<void*>(addr), &mem, nbytes, &r) && r == nbytes)
            {
                value = mem;
                haveValue = true;
            }
        }

        if (haveValue && value != 0)
            return ExecutionStatus::ExceptionIntOverflow;

        return ExecutionStatus::ExceptionIntDivideError;
    }

    static DebugStatus handleException(Context* ctx, const EXCEPTION_RECORD& record)
    {
        const auto exceptionAddress = reinterpret_cast<uintptr_t>(record.ExceptionAddress);

        if (record.ExceptionCode == EXCEPTION_BREAKPOINT)
        {
            if (exceptionAddress == ctx->breakAddr)
            {
                // fmt::print("Successfully executed instruction\n");
                ctx->status = ExecutionStatus::Success;
                return DebugStatus::Exit;
            }
            else if (exceptionAddress == ctx->codeBase)
            {
                // Entry breakpoint.
                return DebugStatus::Exit;
            }
            else if (ctx->breakAddr == 0)
            {
                // fmt::print("System breakpoint\n");
                return DebugStatus::SystemBreak;
            }
        }
        else if (record.ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
        {
            ctx->status = classifyDivideError(ctx, exceptionAddress);
            return DebugStatus::Faulted;
        }
        else if (record.ExceptionCode == EXCEPTION_INT_OVERFLOW)
        {
            ctx->status = ExecutionStatus::ExceptionIntOverflow;
            return DebugStatus::Faulted;
        }
        else if (record.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION)
        {
            ctx->status = ExecutionStatus::IllegalInstruction;
            return DebugStatus::Faulted;
        }

        fmt::print("Exception code: {:X}\n", record.ExceptionCode);
        fmt::print("Exception flags: {:X}\n", record.ExceptionFlags);
        fmt::print("Exception address: {:X}\n", exceptionAddress);
        fmt::print("Number of parameters: {}\n", record.NumberParameters);
        for (DWORD i = 0; i < record.NumberParameters; ++i)
        {
            fmt::print("Parameter {}: {}\n", i, record.ExceptionInformation[i]);
        }

        if (ctx->codeBase >= exceptionAddress && exceptionAddress < ctx->codeBase + ctx->codeSize)
        {
            dumpDisassembly(ctx, exceptionAddress);
        }

        return DebugStatus::Faulted;
    }

    static DebugStatus handleDbgEvent(Context* ctx, const DEBUG_EVENT& dbgEvent)
    {
        switch (dbgEvent.dwDebugEventCode)
        {
            case EXCEPTION_DEBUG_EVENT:
                return handleException(ctx, dbgEvent.u.Exception.ExceptionRecord);
            case CREATE_PROCESS_DEBUG_EVENT:
                CloseHandle(dbgEvent.u.CreateProcessInfo.hFile);
                break;
            case LOAD_DLL_DEBUG_EVENT:
                CloseHandle(dbgEvent.u.LoadDll.hFile);
                break;
            default:
                break;
        }

        return DebugStatus::Continue;
    }

    static HANDLE killOnCloseJob()
    {
        static HANDLE job = []() -> HANDLE {
            HANDLE handle = CreateJobObjectW(nullptr, nullptr);
            if (handle != nullptr)
            {
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(handle, JobObjectExtendedLimitInformation, &info, sizeof(info));
            }
            return handle;
        }();
        return job;
    }

    static bool spawnProcess(Context* ctx)
    {
        ctx->startupInfo.cb = sizeof(ctx->startupInfo);
        ctx->startupInfo.dwFlags = STARTF_USESHOWWINDOW;
        ctx->startupInfo.wShowWindow = SW_HIDE;

        wchar_t exePath[2048]{};
        GetModuleFileNameW(nullptr, exePath, 2048);

        std::wstring cmdLine = L"\"";
        cmdLine += exePath;
        cmdLine += L"\" --sandbox";

        if (!CreateProcessW(
                nullptr, cmdLine.data(), nullptr, nullptr, FALSE, DEBUG_PROCESS, nullptr, nullptr, &ctx->startupInfo,
                &ctx->processInfo))
        {
            return false;
        }

        if (HANDLE job = killOnCloseJob(); job != nullptr)
            AssignProcessToJobObject(job, ctx->processInfo.hProcess);

        // Consume all debug events until the first breakpoint.
        auto& dbgEvent = ctx->dbgEvent;
        while (WaitForDebugEvent(&dbgEvent, INFINITE))
        {
            auto status = handleDbgEvent(ctx, dbgEvent);
            if (status == DebugStatus::Continue)
            {
                // Ignore.
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
            }
            else if (status == DebugStatus::SystemBreak)
            {
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
                break;
            }
            else
            {
                Logging::println("Unexpected event");
                break;
            }
        }

        return true;
    }

    static std::vector<ZydisRegister> getUsedGPRegister(const ZydisDisassembledInstruction& instr)
    {
        std::vector<ZydisRegister> regs;

        for (size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];

            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                auto regId = ZydisRegisterGetLargestEnclosing(instr.info.machine_mode, op.reg.value);
                auto regCls = ZydisRegisterGetClass(regId);

                if (regCls == ZYDIS_REGCLASS_GPR32 || regCls == ZYDIS_REGCLASS_GPR64)
                {
                    regs.push_back(regId);
                }
            }
        }

        return regs;
    }

    static constexpr std::array<std::byte, 0x1000> kNulledPage{};

    static bool setupCode(Context* ctx, std::span<const std::uint8_t> code)
    {
        SIZE_T written{};

        auto* imageBase = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
        auto* remoteCodeAddr = imageBase;

        DWORD oldProtect = 0;
        if (!VirtualProtectEx(ctx->processInfo.hProcess, remoteCodeAddr, code.size() + 2, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return false;
        }

        // Clear the page to avoid any accidental execution of existing code.
        if (!WriteProcessMemory(ctx->processInfo.hProcess, remoteCodeAddr, kNulledPage.data(), sizeof(kNulledPage), &written))
        {
            return false;
        }

        const uint8_t breakpoint[] = { 0xCC };

        auto* cur = remoteCodeAddr;

        // Write breakpoint before the code.
        if (!WriteProcessMemory(ctx->processInfo.hProcess, cur, breakpoint, sizeof(breakpoint), &written))
        {
            return false;
        }
        cur += 1;

        // Write code to test.
        const auto codeAddr = reinterpret_cast<std::uintptr_t>(cur);
        if (!WriteProcessMemory(ctx->processInfo.hProcess, cur, code.data(), code.size(), &written))
        {
            return false;
        }
        cur += code.size();

        // Write breakpoint after the code.
        const auto breakAddr = reinterpret_cast<std::uintptr_t>(cur);
        if (!WriteProcessMemory(ctx->processInfo.hProcess, cur, breakpoint, sizeof(breakpoint), &written))
        {
            return false;
        }
        cur += 1;

        ctx->codeBase = reinterpret_cast<std::uintptr_t>(remoteCodeAddr);
        ctx->codeAddr = codeAddr;
        ctx->breakAddr = breakAddr;
        ctx->codeSize = cur - remoteCodeAddr;

        return true;
    }

    static bool setupThread(Context* ctx)
    {
        // Setup a little breakpoint stub.
        auto* bpCave = VirtualAllocEx(
            ctx->processInfo.hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (bpCave == nullptr)
        {
            Logging::println("VirtualAllocEx failed: {:X}", GetLastError());
            return false;
        }

        const std::uint8_t stubCode[] = {
            0xCC,       // int3
            0xEB, 0xFE, // jmp $+0
        };

        SIZE_T written{};
        if (!WriteProcessMemory(ctx->processInfo.hProcess, bpCave, stubCode, sizeof(stubCode), &written))
        {
            Logging::println("WriteProcessMemory failed: {:X}", GetLastError());
            return false;
        }

        // Spawn thread.
        auto hThread = CreateRemoteThread(
            ctx->processInfo.hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(bpCave), nullptr, 0, nullptr);

        if (hThread == nullptr)
        {
            Logging::println("CreateRemoteThread failed: {:X}", GetLastError());
            return false;
        }

        ctx->hThread = hThread;
        // Temporarily becomes our code base.
        ctx->codeBase = reinterpret_cast<std::uintptr_t>(bpCave);

        // Wait for the entry breakpoint.
        auto& dbgEvent = ctx->dbgEvent;
        while (WaitForDebugEvent(&dbgEvent, INFINITE))
        {
            auto status = handleDbgEvent(ctx, dbgEvent);
            if (status == DebugStatus::Exit)
            {
                ctx->codeBase = 0;
                break;
            }
            else if (status == DebugStatus::Faulted)
            {
                Logging::println("Thread faulted during setup");
                return false;
            }
            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
        }

        return true;
    }

    static bool setupThreadContext(Context* ctx)
    {
        ctx->xstateMask = GetEnabledXStateFeatures();

        DWORD contextSize = 0;
        InitializeContext2(nullptr, CONTEXT_ALL | CONTEXT_XSTATE, nullptr, &contextSize, ctx->xstateMask);
        ctx->contextStorage.resize(contextSize);

        PCONTEXT pctx = nullptr;
        if (!InitializeContext2(ctx->contextStorage.data(), CONTEXT_ALL | CONTEXT_XSTATE, &pctx, &contextSize, ctx->xstateMask))
        {
            return false;
        }
        ctx->threadContext = pctx;

        ctx->threadContext->ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(ctx->hThread, ctx->threadContext))
        {
            return false;
        }

        // Clear all registers.
        ctx->threadContext->Rax = 0;
        ctx->threadContext->Rcx = 0;
        ctx->threadContext->Rdx = 0;
        ctx->threadContext->Rbx = 0;
        ctx->threadContext->Rsp = 0;
        ctx->threadContext->Rbp = 0;
        ctx->threadContext->Rsi = 0;
        ctx->threadContext->Rdi = 0;
        ctx->threadContext->R8 = 0;
        ctx->threadContext->R9 = 0;
        ctx->threadContext->R10 = 0;
        ctx->threadContext->R11 = 0;
        ctx->threadContext->R12 = 0;
        ctx->threadContext->R13 = 0;
        ctx->threadContext->R14 = 0;
        ctx->threadContext->R15 = 0;
        ctx->threadContext->Rip = ctx->codeBase + 1;

        return true;
    }

    static DWORD computeContextFlags(ZydisMachineMode mode, std::span<const std::uint8_t> code)
    {
        ZydisDisassembledInstruction instr;
        if (!ZYAN_SUCCESS(ZydisDisassembleIntel(mode, 0, code.data(), code.size(), &instr)))
            return CONTEXT_ALL;

        DWORD flags = CONTEXT_CONTROL | CONTEXT_INTEGER;
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
                case ZYDIS_REGCLASS_YMM:
                case ZYDIS_REGCLASS_ZMM:
                case ZYDIS_REGCLASS_MASK:
                    return CONTEXT_ALL | CONTEXT_XSTATE;
                case ZYDIS_REGCLASS_XMM:
                    if (op.reg.value >= ZYDIS_REGISTER_XMM16)
                        return CONTEXT_ALL | CONTEXT_XSTATE;
                    flags = CONTEXT_ALL;
                    break;
                default:
                    flags = CONTEXT_ALL;
            }
        }

        return flags;
    }

    Context* prepare(ZydisMachineMode mode, std::span<const std::uint8_t> code)
    {
        auto ctx = new Context{};

        if (!spawnProcess(ctx))
        {
            delete ctx;
            return nullptr;
        }

        if (!setupThread(ctx))
        {
            delete ctx;
            return nullptr;
        }

        if (!setupCode(ctx, code))
        {
            delete ctx;
            return nullptr;
        }

        if (!setupThreadContext(ctx))
        {
            delete ctx;
            return nullptr;
        }

        ctx->contextFlags = computeContextFlags(mode, code);

        if ((ctx->contextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE)
        {
            ctx->threadContext->ContextFlags = ctx->contextFlags;
            SetXStateFeaturesMask(ctx->threadContext, ctx->xstateMask & ~static_cast<DWORD64>(3));
        }

        return ctx;
    }

    bool reset(Context* ctx, ZydisMachineMode mode, std::span<const std::uint8_t> code)
    {
        if (!setupCode(ctx, code))
            return false;

        ctx->threadContext->Rax = 0;
        ctx->threadContext->Rcx = 0;
        ctx->threadContext->Rdx = 0;
        ctx->threadContext->Rbx = 0;
        ctx->threadContext->Rsp = 0;
        ctx->threadContext->Rbp = 0;
        ctx->threadContext->Rsi = 0;
        ctx->threadContext->Rdi = 0;
        ctx->threadContext->R8 = 0;
        ctx->threadContext->R9 = 0;
        ctx->threadContext->R10 = 0;
        ctx->threadContext->R11 = 0;
        ctx->threadContext->R12 = 0;
        ctx->threadContext->R13 = 0;
        ctx->threadContext->R14 = 0;
        ctx->threadContext->R15 = 0;

        ctx->contextFlags = computeContextFlags(mode, code);

        if ((ctx->contextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE)
        {
            ctx->threadContext->ContextFlags = ctx->contextFlags;
            SetXStateFeaturesMask(ctx->threadContext, ctx->xstateMask & ~static_cast<DWORD64>(3));
        }

        return true;
    }

    std::span<std::uint8_t> getContextReg(Context* ctx, ZydisRegister reg)
    {
        auto getRegData = [&](auto& dst) {
            //
            return std::span(reinterpret_cast<std::uint8_t*>(&dst), sizeof(dst));
        };

        switch (reg)
        {
            case ZYDIS_REGISTER_RAX:
                return getRegData(ctx->threadContext->Rax);
            case ZYDIS_REGISTER_RCX:
                return getRegData(ctx->threadContext->Rcx);
            case ZYDIS_REGISTER_RDX:
                return getRegData(ctx->threadContext->Rdx);
            case ZYDIS_REGISTER_RBX:
                return getRegData(ctx->threadContext->Rbx);
            case ZYDIS_REGISTER_RSP:
                return getRegData(ctx->threadContext->Rsp);
            case ZYDIS_REGISTER_RBP:
                return getRegData(ctx->threadContext->Rbp);
            case ZYDIS_REGISTER_RSI:
                return getRegData(ctx->threadContext->Rsi);
            case ZYDIS_REGISTER_RDI:
                return getRegData(ctx->threadContext->Rdi);
            case ZYDIS_REGISTER_R8:
                return getRegData(ctx->threadContext->R8);
            case ZYDIS_REGISTER_R9:
                return getRegData(ctx->threadContext->R9);
            case ZYDIS_REGISTER_R10:
                return getRegData(ctx->threadContext->R10);
            case ZYDIS_REGISTER_R11:
                return getRegData(ctx->threadContext->R11);
            case ZYDIS_REGISTER_R12:
                return getRegData(ctx->threadContext->R12);
            case ZYDIS_REGISTER_R13:
                return getRegData(ctx->threadContext->R13);
            case ZYDIS_REGISTER_R14:
                return getRegData(ctx->threadContext->R14);
            case ZYDIS_REGISTER_R15:
                return getRegData(ctx->threadContext->R15);
            case ZYDIS_REGISTER_RIP:
                return getRegData(ctx->threadContext->Rip);
            case ZYDIS_REGISTER_RFLAGS:
                [[fallthrough]];
            case ZYDIS_REGISTER_EFLAGS:
                return getRegData(ctx->threadContext->EFlags);
            case ZYDIS_REGISTER_XMM0:
                return getRegData(ctx->threadContext->Xmm0);
            case ZYDIS_REGISTER_XMM1:
                return getRegData(ctx->threadContext->Xmm1);
            case ZYDIS_REGISTER_XMM2:
                return getRegData(ctx->threadContext->Xmm2);
            case ZYDIS_REGISTER_XMM3:
                return getRegData(ctx->threadContext->Xmm3);
            case ZYDIS_REGISTER_XMM4:
                return getRegData(ctx->threadContext->Xmm4);
            case ZYDIS_REGISTER_XMM5:
                return getRegData(ctx->threadContext->Xmm5);
            case ZYDIS_REGISTER_XMM6:
                return getRegData(ctx->threadContext->Xmm6);
            case ZYDIS_REGISTER_XMM7:
                return getRegData(ctx->threadContext->Xmm7);
            case ZYDIS_REGISTER_XMM8:
                return getRegData(ctx->threadContext->Xmm8);
            case ZYDIS_REGISTER_XMM9:
                return getRegData(ctx->threadContext->Xmm9);
            case ZYDIS_REGISTER_XMM10:
                return getRegData(ctx->threadContext->Xmm10);
            case ZYDIS_REGISTER_XMM11:
                return getRegData(ctx->threadContext->Xmm11);
            case ZYDIS_REGISTER_XMM12:
                return getRegData(ctx->threadContext->Xmm12);
            case ZYDIS_REGISTER_XMM13:
                return getRegData(ctx->threadContext->Xmm13);
            case ZYDIS_REGISTER_XMM14:
                return getRegData(ctx->threadContext->Xmm14);
            case ZYDIS_REGISTER_XMM15:
                return getRegData(ctx->threadContext->Xmm15);
            case ZYDIS_REGISTER_ST0:
                return getRegData(ctx->threadContext->FltSave.FloatRegisters[0]);
            case ZYDIS_REGISTER_ST1:
                return getRegData(ctx->threadContext->FltSave.FloatRegisters[1]);
            case ZYDIS_REGISTER_ST2:
                return getRegData(ctx->threadContext->FltSave.FloatRegisters[2]);
            case ZYDIS_REGISTER_ST3:
                return getRegData(ctx->threadContext->FltSave.FloatRegisters[3]);
            case ZYDIS_REGISTER_ST4:
                return getRegData(ctx->threadContext->FltSave.FloatRegisters[4]);
            case ZYDIS_REGISTER_ST5:
                return getRegData(ctx->threadContext->FltSave.FloatRegisters[5]);
            case ZYDIS_REGISTER_ST6:
                return getRegData(ctx->threadContext->FltSave.FloatRegisters[6]);
            case ZYDIS_REGISTER_ST7:
                return getRegData(ctx->threadContext->FltSave.FloatRegisters[7]);
            case ZYDIS_REGISTER_X87STATUS:
                return getRegData(ctx->threadContext->FltSave.StatusWord);
            case ZYDIS_REGISTER_X87CONTROL:
                return getRegData(ctx->threadContext->FltSave.ControlWord);
            case ZYDIS_REGISTER_X87TAG:
                return getRegData(ctx->threadContext->FltSave.TagWord);
            case ZYDIS_REGISTER_MXCSR:
                return getRegData(ctx->threadContext->FltSave.MxCsr);
        }

        assert(false);
        return {};
    }

    static std::uint8_t* xstatePtr(Context* ctx, DWORD feature)
    {
        DWORD length = 0;
        return reinterpret_cast<std::uint8_t*>(LocateXStateFeature(ctx->threadContext, feature, &length));
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

    static sfl::small_vector<std::uint8_t, 16> gatherWideReg(Context* ctx, ZydisRegister reg)
    {
        unsigned idx = 0, width = 0;
        bool isMask = false;
        wideRegLayout(reg, idx, width, isMask);

        sfl::small_vector<std::uint8_t, 16> out(width, std::uint8_t{ 0 });

        if (isMask)
        {
            if (auto* k = xstatePtr(ctx, XSTATE_AVX512_KMASK))
                std::memcpy(out.data(), k + idx * 8, 8);
            return out;
        }

        if (idx < 16)
        {
            std::memcpy(out.data(), &ctx->threadContext->FltSave.XmmRegisters[idx], 16);
            if (width >= 32)
                if (auto* avx = xstatePtr(ctx, XSTATE_AVX))
                    std::memcpy(out.data() + 16, avx + idx * 16, 16);
            if (width >= 64)
                if (auto* zh = xstatePtr(ctx, XSTATE_AVX512_ZMM_H))
                    std::memcpy(out.data() + 32, zh + idx * 32, 32);
        }
        else
        {
            if (auto* hi = xstatePtr(ctx, XSTATE_AVX512_ZMM))
                std::memcpy(out.data(), hi + (idx - 16) * 64, width);
        }
        return out;
    }

    static void scatterWideReg(Context* ctx, ZydisRegister reg, std::span<const std::uint8_t> data)
    {
        unsigned idx = 0, width = 0;
        bool isMask = false;
        wideRegLayout(reg, idx, width, isMask);

        const std::size_t n = data.size();

        if (isMask)
        {
            if (auto* k = xstatePtr(ctx, XSTATE_AVX512_KMASK))
                std::memcpy(k + idx * 8, data.data(), std::min<std::size_t>(8, n));
            return;
        }

        if (idx < 16)
        {
            std::memcpy(&ctx->threadContext->FltSave.XmmRegisters[idx], data.data(), std::min<std::size_t>(16, n));
            if (n > 16)
                if (auto* avx = xstatePtr(ctx, XSTATE_AVX))
                    std::memcpy(avx + idx * 16, data.data() + 16, std::min<std::size_t>(16, n - 16));
            if (n > 32)
                if (auto* zh = xstatePtr(ctx, XSTATE_AVX512_ZMM_H))
                    std::memcpy(zh + idx * 32, data.data() + 32, std::min<std::size_t>(32, n - 32));
        }
        else
        {
            if (auto* hi = xstatePtr(ctx, XSTATE_AVX512_ZMM))
                std::memcpy(hi + (idx - 16) * 64, data.data(), std::min<std::size_t>(width, n));
        }
    }

    bool setRegBytes(Context* ctx, ZydisRegister reg, std::span<const std::uint8_t> data)
    {
        if (isWideOrMaskReg(reg))
        {
            scatterWideReg(ctx, reg, data);
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
            return gatherWideReg(ctx, reg);

        const auto s = getContextReg(ctx, reg);
        return sfl::small_vector<std::uint8_t, 16>(s.begin(), s.end());
    }

    bool execute(Context* ctx)
    {
        ctx->status = ExecutionStatus::Idle;

        ctx->threadContext->ContextFlags = ctx->contextFlags;
        if ((ctx->contextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE)
            SetXStateFeaturesMask(ctx->threadContext, ctx->xstateMask & ~static_cast<DWORD64>(3));
        ctx->threadContext->Rip = ctx->codeBase + 1;

        // Mark all x87 registers valid (non-empty) and force the stack top to 0, so in-place
        // x87 ops read their operands from the physical registers the harness mapped ST(i) to.
        // Without this the default FPU state tags every register empty and stack ops fault.
        ctx->threadContext->FltSave.TagWord = 0xFF;
        ctx->threadContext->FltSave.StatusWord &= 0xC7FF;

        if (SetThreadContext(ctx->hThread, ctx->threadContext) == FALSE)
        {
            Logging::println("SetThreadContext failed: {:X}", GetLastError());
            return false;
        }

        auto& dbgEvent = ctx->dbgEvent;
        if (!ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE))
        {
            Logging::println("ContinueDebugEvent failed: {:X}", GetLastError());
            return false;
        }

        // Wait for the breakpoint to appear or an exception to occur.
        while (WaitForDebugEvent(&dbgEvent, INFINITE))
        {
            bool breakOut = false;

            auto status = handleDbgEvent(ctx, dbgEvent);
            if (status == DebugStatus::Faulted)
            {
                break;
            }
            else if (status == DebugStatus::Exit)
            {
                break;
            }

            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
            if (breakOut)
                break;
        }

        ctx->threadContext->ContextFlags = ctx->contextFlags;
        if ((ctx->contextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE)
            SetXStateFeaturesMask(ctx->threadContext, ctx->xstateMask & ~static_cast<DWORD64>(3));
        if (!GetThreadContext(ctx->hThread, ctx->threadContext))
        {
            return false;
        }

        return true;
    }

    void pinThread(Context* ctx, unsigned core)
    {
        if (ctx == nullptr || ctx->hThread == nullptr)
            return;
        SetThreadAffinityMask(ctx->hThread, static_cast<DWORD_PTR>(1) << core);
    }

    void cleanup(Context* ctx)
    {
        // Signal Termination
        TerminateProcess(ctx->processInfo.hProcess, 0);

        // Continue last event.
        ContinueDebugEvent(ctx->dbgEvent.dwProcessId, ctx->dbgEvent.dwThreadId, DBG_CONTINUE);

        // Poll debug events so the process can exit.
        for (;;)
        {
            DEBUG_EVENT dbgEvent{};
            if (!WaitForDebugEvent(&dbgEvent, INFINITE))
                break;

            if (dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            {
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
                break;
            }

            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
        }

        CloseHandle(ctx->processInfo.hProcess);
        CloseHandle(ctx->processInfo.hThread);
        CloseHandle(ctx->hThread);

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