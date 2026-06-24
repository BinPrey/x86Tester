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
                return true;
        }
        return false;
    }

    inline sfl::static_vector<ZydisRegister, 5> sortRegs(const sfl::small_flat_set<ZydisRegister, 5>& regs)
    {
        sfl::static_vector<ZydisRegister, 5> res(regs.begin(), regs.end());
        std::sort(res.begin(), res.end(), [](auto a, auto b) {
            return ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, a) > ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, b);
        });
        return res;
    }

    inline sfl::static_vector<ZydisRegister, 5> getRegsModified(const ZydisDisassembledInstruction& instr)
    {
        sfl::small_flat_set<ZydisRegister, 5> regs;
        for (std::size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0)
            {
                if (!isRegFiltered(op.reg.value))
                    regs.insert(op.reg.value);
            }
        }
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

    inline sfl::static_vector<ZydisRegister, 5> getRegsRead(const ZydisDisassembledInstruction& instr)
    {
        sfl::small_flat_set<ZydisRegister, 5> regs;
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
            const auto bigReg = getRootReg(instr.info.machine_mode, reg);
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

    std::vector<TestBitInfo> generateTestMatrix(const ZydisDisassembledInstruction& instr);

} // namespace x86Tester::Generator
