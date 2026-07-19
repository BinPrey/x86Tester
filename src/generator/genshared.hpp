#pragma once

#include "generator.hpp"

#include <Zydis/Disassembler.h>

#include <algorithm>
#include <cstdint>
#include <sfl/small_flat_set.hpp>
#include <sfl/static_vector.hpp>
#include <vector>

namespace x86Tester::Generator
{
    struct TestBitInfo
    {
        ExceptionType exceptionType;
        ZydisRegister reg;
        std::uint16_t bitPos;
        std::uint8_t expectedBitValue;
        std::uint32_t mask = 0;
        std::uint32_t expectedValue = 0;
    };

    inline bool isRegFiltered(ZydisRegister reg)
    {
        switch (reg)
        {
            case ZYDIS_REGISTER_NONE:
            case ZYDIS_REGISTER_EIP:
            case ZYDIS_REGISTER_RIP:
            case ZYDIS_REGISTER_FLAGS:
            case ZYDIS_REGISTER_EFLAGS:
            case ZYDIS_REGISTER_RFLAGS:
            case ZYDIS_REGISTER_PKRU:
                return true;
        }
        return false;
    }

    inline bool x87ReadsRoundingControl(ZydisMnemonic m)
    {
        switch (m)
        {
            case ZYDIS_MNEMONIC_FADD:
            case ZYDIS_MNEMONIC_FADDP:
            case ZYDIS_MNEMONIC_FIADD:
            case ZYDIS_MNEMONIC_FSUB:
            case ZYDIS_MNEMONIC_FSUBP:
            case ZYDIS_MNEMONIC_FISUB:
            case ZYDIS_MNEMONIC_FSUBR:
            case ZYDIS_MNEMONIC_FSUBRP:
            case ZYDIS_MNEMONIC_FISUBR:
            case ZYDIS_MNEMONIC_FMUL:
            case ZYDIS_MNEMONIC_FMULP:
            case ZYDIS_MNEMONIC_FIMUL:
            case ZYDIS_MNEMONIC_FDIV:
            case ZYDIS_MNEMONIC_FDIVP:
            case ZYDIS_MNEMONIC_FIDIV:
            case ZYDIS_MNEMONIC_FDIVR:
            case ZYDIS_MNEMONIC_FDIVRP:
            case ZYDIS_MNEMONIC_FIDIVR:
            case ZYDIS_MNEMONIC_FSQRT:
            case ZYDIS_MNEMONIC_FRNDINT:
            case ZYDIS_MNEMONIC_FSCALE:
            case ZYDIS_MNEMONIC_FST:
            case ZYDIS_MNEMONIC_FSTP:
            case ZYDIS_MNEMONIC_FIST:
            case ZYDIS_MNEMONIC_FISTP:
            case ZYDIS_MNEMONIC_FSIN:
            case ZYDIS_MNEMONIC_FCOS:
            case ZYDIS_MNEMONIC_FSINCOS:
            case ZYDIS_MNEMONIC_FPTAN:
            case ZYDIS_MNEMONIC_FPATAN:
            case ZYDIS_MNEMONIC_F2XM1:
            case ZYDIS_MNEMONIC_FYL2X:
            case ZYDIS_MNEMONIC_FYL2XP1:
                return true;
        }
        return false;
    }

    inline bool x87WritesControl(ZydisMnemonic m)
    {
        switch (m)
        {
            case ZYDIS_MNEMONIC_FLDCW:
            case ZYDIS_MNEMONIC_FNINIT:
            case ZYDIS_MNEMONIC_FLDENV:
            case ZYDIS_MNEMONIC_FRSTOR:
                return true;
        }
        return false;
    }

    inline sfl::static_vector<ZydisRegister, 7> sortRegs(const sfl::small_flat_set<ZydisRegister, 7>& regs)
    {
        sfl::static_vector<ZydisRegister, 7> res(regs.begin(), regs.end());
        std::sort(res.begin(), res.end(), [](auto a, auto b) {
            return ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, a) > ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, b);
        });
        return res;
    }

    inline sfl::static_vector<ZydisRegister, 7> getRegsModified(const ZydisDisassembledInstruction& instr)
    {
        sfl::small_flat_set<ZydisRegister, 7> regs;
        for (std::size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0)
            {
                if (!isRegFiltered(op.reg.value))
                    regs.insert(op.reg.value);
            }
        }
        if (x87WritesControl(instr.info.mnemonic))
            regs.insert(ZYDIS_REGISTER_X87CONTROL);
        return sortRegs(regs);
    }

    inline ZydisRegister getRootReg(ZydisMachineMode mode, ZydisRegister reg)
    {
        const auto regCls = ZydisRegisterGetClass(reg);
        switch (regCls)
        {
            // General purpose registers
            case ZYDIS_REGCLASS_GPR8:
            case ZYDIS_REGCLASS_GPR16:
            case ZYDIS_REGCLASS_GPR32:
            case ZYDIS_REGCLASS_GPR64:
            case ZYDIS_REGCLASS_FLAGS:
                return ZydisRegisterGetLargestEnclosing(mode, reg);
        }
        return reg;
    }

    inline ZydisRegister getEnclosingReg(ZydisMachineMode mode, ZydisRegister reg)
    {
        switch (ZydisRegisterGetClass(reg))
        {
            case ZYDIS_REGCLASS_GPR8:
            case ZYDIS_REGCLASS_GPR16:
            case ZYDIS_REGCLASS_GPR32:
            case ZYDIS_REGCLASS_GPR64:
            case ZYDIS_REGCLASS_FLAGS:
            case ZYDIS_REGCLASS_XMM:
            case ZYDIS_REGCLASS_YMM:
            case ZYDIS_REGCLASS_ZMM:
                return ZydisRegisterGetLargestEnclosing(mode, reg);
        }
        return reg;
    }

    inline sfl::static_vector<ZydisRegister, 7> getRegsRead(const ZydisDisassembledInstruction& instr)
    {
        sfl::small_flat_set<ZydisRegister, 7> regs;
        for (std::size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                regs.insert(op.reg.value);
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (op.mem.base != ZYDIS_REGISTER_NONE && !isRegFiltered(op.mem.base))
                    regs.insert(op.mem.base);
                if (op.mem.index != ZYDIS_REGISTER_NONE && !isRegFiltered(op.mem.index))
                    regs.insert(op.mem.index);
            }
        }

        // Mark registers that are smaller than 32 bit also as read, the upper bits remain unaffected.
        for (std::size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                const auto regCls = ZydisRegisterGetClass(op.reg.value);
                if (regCls == ZydisRegisterClass::ZYDIS_REGCLASS_GPR16 || regCls == ZydisRegisterClass::ZYDIS_REGCLASS_GPR8)
                {
                    regs.insert(op.reg.value);
                }
            }
        }

        if (x87ReadsRoundingControl(instr.info.mnemonic))
            regs.insert(ZYDIS_REGISTER_X87CONTROL);

        const auto remapReg = [](auto& oldReg) {
            if (oldReg == ZYDIS_REGISTER_AH)
                return ZYDIS_REGISTER_AX;
            if (oldReg == ZYDIS_REGISTER_BH)
                return ZYDIS_REGISTER_BX;
            if (oldReg == ZYDIS_REGISTER_CH)
                return ZYDIS_REGISTER_CX;
            if (oldReg == ZYDIS_REGISTER_DH)
                return ZYDIS_REGISTER_DX;
            return oldReg;
        };

        sfl::small_flat_map<ZydisRegister, ZydisRegister, 5> regMap;
        // Some registers may overlap, we have to turn them into a single register with largest size encountered.
        for (const auto& reg : regs)
        {
            const auto bigReg = getEnclosingReg(instr.info.machine_mode, reg);
            auto newReg = remapReg(reg);
            if (auto it = regMap.find(bigReg); it != regMap.end())
            {
                if (ZydisRegisterGetWidth(instr.info.machine_mode, newReg)
                    > ZydisRegisterGetWidth(instr.info.machine_mode, it->second))
                {
                    // Pick bigger.
                    it->second = newReg;
                }
            }
            else
                regMap[bigReg] = newReg;
        }

        regs.clear();
        for (const auto& [bigReg, reg] : regMap)
        {
            regs.insert(reg);
        }

        return sortRegs(regs);
    }

    inline std::uint32_t getFlagsModified(const ZydisDisassembledInstruction& instr)
    {
        std::uint32_t flags = 0;
        flags |= instr.info.cpu_flags->modified;
        return flags;
    }

    inline std::uint32_t getFlagsSet0(const ZydisDisassembledInstruction& instr)
    {
        std::uint32_t flags = 0;
        flags |= instr.info.cpu_flags->set_0;
        return flags;
    }

    inline std::uint32_t getFlagsSet1(const ZydisDisassembledInstruction& instr)
    {
        std::uint32_t flags = 0;
        flags |= instr.info.cpu_flags->set_1;
        return flags;
    }

    enum class MemKind
    {
        None,
        Stack,
        String,
        Disp,
    };

    struct MemOperand
    {
        MemKind kind = MemKind::None;
        bool reads = false;
        bool writes = false;
        std::size_t size = 0;
        std::int64_t disp = 0;
        ZydisRegister base = ZYDIS_REGISTER_NONE;
    };

    struct MemInfo
    {
        sfl::static_vector<MemOperand, 2> ops;

        bool present() const
        {
            return !ops.empty();
        }

        bool sweep() const
        {
            for (const auto& op : ops)
                if (op.kind == MemKind::Stack || op.kind == MemKind::String)
                    return true;
            return false;
        }
    };

    inline MemInfo getMemInfo(const ZydisDisassembledInstruction& instr)
    {
        MemInfo info;
        for (std::size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type != ZYDIS_OPERAND_TYPE_MEMORY || op.mem.type == ZYDIS_MEMOP_TYPE_AGEN)
                continue;

            const bool stack = op.mem.base == ZYDIS_REGISTER_RSP || op.mem.base == ZYDIS_REGISTER_ESP
                || op.mem.base == ZYDIS_REGISTER_SP;
            const bool str = op.mem.base == ZYDIS_REGISTER_RDI || op.mem.base == ZYDIS_REGISTER_EDI
                || op.mem.base == ZYDIS_REGISTER_DI || op.mem.base == ZYDIS_REGISTER_RSI
                || op.mem.base == ZYDIS_REGISTER_ESI || op.mem.base == ZYDIS_REGISTER_SI;
            const bool dispOnly = op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE;

            MemOperand mo;
            if (stack)
            {
                mo.kind = MemKind::Stack;
                mo.base = ZYDIS_REGISTER_RSP;
            }
            else if (str)
            {
                mo.kind = MemKind::String;
                mo.base = ZydisRegisterGetLargestEnclosing(instr.info.machine_mode, op.mem.base);
            }
            else if (dispOnly)
            {
                mo.kind = MemKind::Disp;
                mo.disp = op.mem.disp.value;
            }
            else
                continue;

            mo.size = op.size / 8;
            if ((op.actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0)
                mo.reads = true;
            if ((op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0)
                mo.writes = true;

            if (info.ops.size() < info.ops.max_size())
                info.ops.push_back(mo);
        }
        return info;
    }

    std::vector<TestBitInfo> generateTestMatrix(const ZydisDisassembledInstruction& instr);

} // namespace x86Tester::Generator
