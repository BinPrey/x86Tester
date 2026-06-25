#include "basegenerator.hpp"
#include "generator.hpp"
#include "genshared.hpp"

#include <Zydis/Disassembler.h>
#include <Zydis/Encoder.h>
extern "C" {
#include <Zydis/Internal/EncoderData.h>
#include <Zydis/Internal/SharedData.h>
}

#include <algorithm>
#include <bit>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fmt/format.h>
#include <memory>
#include <random>
#include <sfl/small_flat_set.hpp>
#include <sfl/static_vector.hpp>
#include <span>
#include <unordered_set>
#include <vector>
#include <x86Tester/execution.hpp>
#include <x86Tester/inputgenerator.hpp>
#include <x86Tester/logging.hpp>

namespace x86Tester::Generator
{
    static sfl::small_vector<ExceptionType, 5> getExceptions(const ZydisDisassembledInstruction& instr)
    {
        sfl::small_vector<ExceptionType, 5> res;

        switch (instr.info.mnemonic)
        {
            case ZYDIS_MNEMONIC_DIV:
            case ZYDIS_MNEMONIC_IDIV:
                // #DE
                res.push_back(ExceptionType::DivideError);
                res.push_back(ExceptionType::IntegerOverflow);
                break;
        }

        return res;
    }

    struct KnownBits
    {
        std::uint64_t zeros = 0;
        std::uint64_t ones = 0;

        bool knownZero(unsigned bit) const
        {
            return ((zeros >> bit) & 1ull) != 0;
        }

        bool knownOne(unsigned bit) const
        {
            return ((ones >> bit) & 1ull) != 0;
        }
    };

    static KnownBits computeKnownReg(const ZydisDisassembledInstruction& instr, unsigned regSize)
    {
        KnownBits kb;

        if (regSize == 0 || regSize > 64)
            return kb;

        const auto& ops = instr.operands;
        if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
            return kb;

        const std::uint64_t mask = (regSize >= 64) ? ~0ull : ((1ull << regSize) - 1);

        const bool srcIsImm = ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
        const std::uint64_t imm = ops[1].imm.value.u;

        const bool regDestAndSrcSame = ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == ops[1].reg.value;

        const unsigned opWidth = instr.info.operand_width;
        const unsigned shiftMask = (opWidth == 64) ? 63u : 31u;

        switch (instr.info.mnemonic)
        {
            case ZYDIS_MNEMONIC_MOV:
                if (srcIsImm)
                {
                    kb.ones = imm & mask;
                    kb.zeros = ~imm & mask;
                }
                break;
            case ZYDIS_MNEMONIC_MOVZX:
            {
                const unsigned srcWidth = ops[1].size;
                if (srcWidth > 0 && srcWidth < regSize)
                    kb.zeros = (~((1ull << srcWidth) - 1)) & mask;
                break;
            }
            case ZYDIS_MNEMONIC_AND:
                if (srcIsImm)
                    kb.zeros = (~imm) & mask;
                break;
            case ZYDIS_MNEMONIC_OR:
                if (srcIsImm)
                    kb.ones = imm & mask;
                break;
            case ZYDIS_MNEMONIC_XOR:
            case ZYDIS_MNEMONIC_SUB:
                if (regDestAndSrcSame)
                    kb.zeros = mask;
                break;
            case ZYDIS_MNEMONIC_ADD:
                if (regDestAndSrcSame)
                    kb.zeros = 1ull & mask;
                break;
            case ZYDIS_MNEMONIC_MUL:
            case ZYDIS_MNEMONIC_IMUL:
                if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    // dest = src * imm: the result is a multiple of imm, so its low
                    // countr_zero(imm) bits are 0 (and the whole result is 0 when imm is 0).
                    if (ops[2].imm.value.u == 0)
                        kb.zeros = mask;
                    else
                    {
                        const unsigned tz = static_cast<unsigned>(std::countr_zero(ops[2].imm.value.u));
                        kb.zeros = ((tz >= 64) ? ~0ull : ((1ull << tz) - 1)) & mask;
                    }
                }
                else if (regDestAndSrcSame)
                {
                    // x*x is a perfect square; squares are 0 or 1 mod 4, so bit 1 is always 0.
                    kb.zeros = 0x2ull & mask;
                }
                break;
            case ZYDIS_MNEMONIC_SHL:
                if (srcIsImm)
                {
                    const unsigned cnt = static_cast<unsigned>(imm) & shiftMask;
                    if (cnt > 0)
                        kb.zeros = ((cnt >= 64) ? ~0ull : ((1ull << cnt) - 1)) & mask;
                }
                break;
            case ZYDIS_MNEMONIC_SHR:
                if (srcIsImm)
                {
                    const unsigned cnt = static_cast<unsigned>(imm) & shiftMask;
                    if (cnt > 0)
                    {
                        if (cnt >= regSize)
                            kb.zeros = mask;
                        else
                            kb.zeros = mask & ~((1ull << (regSize - cnt)) - 1);
                    }
                }
                break;
            case ZYDIS_MNEMONIC_LEA:
            {
                const unsigned addrW = instr.info.address_width;
                if (addrW < regSize)
                    kb.zeros |= mask & ~((1ull << addrW) - 1);

                const auto& m = ops[1].mem;
                const std::uint64_t disp = static_cast<std::uint64_t>(m.disp.value);

                if (m.base != ZYDIS_REGISTER_NONE && m.index == m.base && m.scale == 1)
                {
                    if ((disp & 1) != 0)
                        kb.ones |= 1ull & mask;
                    else
                        kb.zeros |= 1ull & mask;
                }
                else if (m.base == ZYDIS_REGISTER_NONE && m.index != ZYDIS_REGISTER_NONE && m.scale > 1)
                {
                    const unsigned sh = static_cast<unsigned>(std::log2(m.scale));
                    const std::uint64_t lowMask = ((sh >= 64) ? ~0ull : ((1ull << sh) - 1)) & mask;
                    kb.ones |= disp & lowMask;
                    kb.zeros |= (~disp) & lowMask;
                }
                break;
            }
            case ZYDIS_MNEMONIC_SETB:
            case ZYDIS_MNEMONIC_SETBE:
            case ZYDIS_MNEMONIC_SETL:
            case ZYDIS_MNEMONIC_SETLE:
            case ZYDIS_MNEMONIC_SETNB:
            case ZYDIS_MNEMONIC_SETNBE:
            case ZYDIS_MNEMONIC_SETNL:
            case ZYDIS_MNEMONIC_SETNLE:
            case ZYDIS_MNEMONIC_SETNO:
            case ZYDIS_MNEMONIC_SETNP:
            case ZYDIS_MNEMONIC_SETNS:
            case ZYDIS_MNEMONIC_SETNZ:
            case ZYDIS_MNEMONIC_SETO:
            case ZYDIS_MNEMONIC_SETP:
            case ZYDIS_MNEMONIC_SETS:
            case ZYDIS_MNEMONIC_SETZ:
                kb.zeros = mask & ~1ull;
                break;
            case ZYDIS_MNEMONIC_BSWAP:
                if (regSize <= 16)
                    kb.zeros = mask;
                break;
            case ZYDIS_MNEMONIC_POPCNT:
            case ZYDIS_MNEMONIC_LZCNT:
            case ZYDIS_MNEMONIC_TZCNT:
            {
                const unsigned resultBits = static_cast<unsigned>(std::log2(regSize)) + 1;
                if (resultBits < regSize)
                    kb.zeros = mask & ~((1ull << resultBits) - 1);
                break;
            }
            case ZYDIS_MNEMONIC_BSF:
            case ZYDIS_MNEMONIC_BSR:
            {
                const unsigned resultBits = static_cast<unsigned>(std::log2(regSize));
                if (resultBits < regSize)
                    kb.zeros = mask & ~((1ull << resultBits) - 1);
                break;
            }
            case ZYDIS_MNEMONIC_CRC32:
            {
                if (regSize == 64)
                    kb.zeros |= mask & ~0xFFFFFFFFull;

                const auto destRoot = ZydisRegisterGetLargestEnclosing(instr.info.machine_mode, ops[0].reg.value);
                if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ZydisRegisterGetLargestEnclosing(instr.info.machine_mode, ops[1].reg.value) == destRoot)
                {
                    unsigned srcOffsetBits = 0;
                    switch (ops[1].reg.value)
                    {
                        case ZYDIS_REGISTER_AH:
                        case ZYDIS_REGISTER_BH:
                        case ZYDIS_REGISTER_CH:
                        case ZYDIS_REGISTER_DH:
                            srcOffsetBits = 8;
                            break;
                    }
                    const unsigned srcBytes = ops[1].size / 8;
                    const unsigned rootWidth = ZydisRegisterGetWidth(instr.info.machine_mode, destRoot);

                    std::uint32_t reachable = 0;
                    for (unsigned i = 0; i < rootWidth; ++i)
                    {
                        const std::uint64_t r = 1ull << i;
                        std::uint32_t c = static_cast<std::uint32_t>(r & 0xFFFFFFFFull);
                        for (unsigned b = 0; b < srcBytes; ++b)
                        {
                            c ^= static_cast<std::uint8_t>((r >> (srcOffsetBits + b * 8)) & 0xFF);
                            for (int k = 0; k < 8; ++k)
                                c = (c >> 1) ^ ((c & 1) ? 0x82F63B78u : 0u);
                        }
                        reachable |= c;
                    }
                    kb.zeros |= (~static_cast<std::uint64_t>(reachable)) & 0xFFFFFFFFull & mask;
                }
                break;
            }
            case ZYDIS_MNEMONIC_BLSMSK:
                kb.ones = 1ull & mask;
                break;
            case ZYDIS_MNEMONIC_BLSR:
                kb.zeros = 1ull & mask;
                break;
            case ZYDIS_MNEMONIC_BTR:
                if (srcIsImm && opWidth > 0)
                {
                    const unsigned b = static_cast<unsigned>(imm % opWidth);
                    if (b < regSize)
                        kb.zeros |= (1ull << b);
                }
                break;
            case ZYDIS_MNEMONIC_BTS:
                if (srcIsImm && opWidth > 0)
                {
                    const unsigned b = static_cast<unsigned>(imm % opWidth);
                    if (b < regSize)
                        kb.ones |= (1ull << b);
                }
                break;
        }

        kb.zeros &= mask;
        kb.ones &= mask;
        return kb;
    }

    static void computeX87StatusMasks(ZydisMnemonic m, std::uint32_t& zeroMask, std::uint32_t& untestMask)
    {
        constexpr std::uint32_t ES = 1u << 7, B = 1u << 15;
        constexpr std::uint32_t TOP = (1u << 11) | (1u << 12) | (1u << 13);
        constexpr std::uint32_t C0 = 1u << 8, C1 = 1u << 9, C2 = 1u << 10, C3 = 1u << 14;

        // ES/B are 0 with masked exceptions; TOP is forced to 0 by the harness and the
        // in-place x87 ops we keep never change it.
        zeroMask = ES | B | TOP;
        untestMask = C0 | C2 | C3;

        switch (m)
        {
            case ZYDIS_MNEMONIC_FABS:
            case ZYDIS_MNEMONIC_FCHS:
            case ZYDIS_MNEMONIC_FLD:
            case ZYDIS_MNEMONIC_FLD1:
            case ZYDIS_MNEMONIC_FLDZ:
            case ZYDIS_MNEMONIC_FLDL2T:
            case ZYDIS_MNEMONIC_FLDL2E:
            case ZYDIS_MNEMONIC_FLDPI:
            case ZYDIS_MNEMONIC_FLDLG2:
            case ZYDIS_MNEMONIC_FLDLN2:
            case ZYDIS_MNEMONIC_FILD:
            case ZYDIS_MNEMONIC_FST:
            case ZYDIS_MNEMONIC_FSTP:
            case ZYDIS_MNEMONIC_FIST:
            case ZYDIS_MNEMONIC_FISTP:
            case ZYDIS_MNEMONIC_FISTTP:
            case ZYDIS_MNEMONIC_FBLD:
            case ZYDIS_MNEMONIC_FBSTP:
            case ZYDIS_MNEMONIC_FXCH:
            case ZYDIS_MNEMONIC_FINCSTP:
            case ZYDIS_MNEMONIC_FDECSTP:
            case ZYDIS_MNEMONIC_FFREE:
            case ZYDIS_MNEMONIC_FNOP:
            case ZYDIS_MNEMONIC_FCOMI:
            case ZYDIS_MNEMONIC_FCOMIP:
            case ZYDIS_MNEMONIC_FUCOMI:
            case ZYDIS_MNEMONIC_FUCOMIP:
                zeroMask |= C1;
                break;
            case ZYDIS_MNEMONIC_FCOM:
            case ZYDIS_MNEMONIC_FCOMP:
            case ZYDIS_MNEMONIC_FCOMPP:
            case ZYDIS_MNEMONIC_FUCOM:
            case ZYDIS_MNEMONIC_FUCOMP:
            case ZYDIS_MNEMONIC_FUCOMPP:
            case ZYDIS_MNEMONIC_FTST:
            case ZYDIS_MNEMONIC_FICOM:
            case ZYDIS_MNEMONIC_FICOMP:
                zeroMask |= C1;
                untestMask = 0;
                break;
            case ZYDIS_MNEMONIC_FXAM:
            case ZYDIS_MNEMONIC_FPREM:
            case ZYDIS_MNEMONIC_FPREM1:
                untestMask = 0;
                break;
            case ZYDIS_MNEMONIC_FNCLEX:
                // Clears the exception flags (IE..SF) and ES; leaves condition codes unchanged.
                zeroMask = 0x00FFu | B | TOP;
                untestMask = C0 | C1 | C2 | C3;
                break;
            case ZYDIS_MNEMONIC_FNINIT:
                // Resets the FPU: the entire status word becomes 0.
                zeroMask = 0xFFFFu;
                untestMask = 0;
                break;
            case ZYDIS_MNEMONIC_FSIN:
            case ZYDIS_MNEMONIC_FCOS:
            case ZYDIS_MNEMONIC_FSINCOS:
            case ZYDIS_MNEMONIC_FPTAN:
                untestMask = C0 | C3;
                break;
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
            case ZYDIS_MNEMONIC_FXTRACT:
            case ZYDIS_MNEMONIC_F2XM1:
            case ZYDIS_MNEMONIC_FYL2X:
            case ZYDIS_MNEMONIC_FYL2XP1:
            case ZYDIS_MNEMONIC_FPATAN:
                break;
            default:
                untestMask |= C1;
                break;
        }
    }

    static unsigned fpConvZeroLowPerLane(const ZydisDisassembledInstruction& instr, bool& packed)
    {
        packed = true;
        switch (instr.info.mnemonic)
        {
            case ZYDIS_MNEMONIC_CVTDQ2PD:
            case ZYDIS_MNEMONIC_VCVTDQ2PD:
            case ZYDIS_MNEMONIC_CVTPI2PD:
                return 22;
            case ZYDIS_MNEMONIC_CVTPS2PD:
            case ZYDIS_MNEMONIC_VCVTPS2PD:
                return 29;
            case ZYDIS_MNEMONIC_CVTSS2SD:
            case ZYDIS_MNEMONIC_VCVTSS2SD:
                packed = false;
                return 29;
            case ZYDIS_MNEMONIC_CVTSI2SD:
            case ZYDIS_MNEMONIC_VCVTSI2SD:
            {
                packed = false;
                for (std::size_t i = 0; i < instr.info.operand_count; ++i)
                {
                    const auto& op = instr.operands[i];
                    if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
                        return op.size == 32 ? 22 : 0;
                    if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
                    {
                        const auto cls = ZydisRegisterGetClass(op.reg.value);
                        if (cls == ZYDIS_REGCLASS_GPR32 || cls == ZYDIS_REGCLASS_GPR64)
                            return op.size == 32 ? 22 : 0;
                    }
                }
                return 0;
            }
        }
        return 0;
    }

    // For a left-shift of a lane by its own value (the self-shift case), the only reachable lane
    // values are c<<c for c in [0, laneWidth). Returns the OR of those, i.e. the bits that can be 1.
    static std::uint64_t selfShlReachableMask(unsigned laneWidth)
    {
        const std::uint64_t laneMask = (laneWidth >= 64) ? ~0ull : ((1ull << laneWidth) - 1);
        std::uint64_t m = 0;
        for (unsigned c = 0; c < laneWidth; ++c)
            m |= (static_cast<std::uint64_t>(c) << c) & laneMask;
        return m;
    }

    std::vector<TestBitInfo> generateTestMatrix(const ZydisDisassembledInstruction& instr)
    {
        const auto regsRead = getRegsRead(instr);
        const auto regsModified = getRegsModified(instr);
        const auto flagsModified = getFlagsModified(instr);
        const auto flagsSet1 = getFlagsSet1(instr);
        const auto flagsSet0 = getFlagsSet0(instr);

        std::vector<TestBitInfo> matrix;

        bool regDestAndSrcSame = false;
        const auto& ops = instr.operands;
        if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            if (ops[0].reg.value == ops[1].reg.value)
                regDestAndSrcSame = true;
        }

        bool testRegZero = true;
        bool testRegOne = true;
        bool rightInputZero = false;
        bool resultAlwaysZero = false;
        bool resultAlwaysOne = false;
        bool compareAlwaysZero = false;
        bool zfAlwaysOne = false;
        bool cfAlwaysOne = false;
        bool pfAlwaysOne = false;
        bool flagsNotUpdated = false;
        bool firstBitAlwaysZero = false;
        bool inputIsImmediate = false;
        size_t numBitsZero = 0;
        size_t numBitsOne = 0;
        std::uint64_t laneOneMask = 0;
        unsigned laneOneWidth = 0;
        bool laneOnePacked = true;
        std::uint32_t laneZeroMask = 0;
        unsigned laneZeroWidth = 0;
        unsigned selfAddLaneWidth = 0;
        unsigned selfSquareLaneWidth = 0;
        unsigned laneKeepWidth = 0;
        unsigned laneKeepBits = 0;
        unsigned laneLowZeroWidth = 0;
        unsigned laneLowZeroBits = 0;
        unsigned shiftSelfLaneWidth = 0;
        bool shiftSelfShl = false;
        bool shiftSelfAllLanes = false;
        std::uint64_t shiftSelfMask = 0;
        unsigned gprShlSelfBits = 0;
        std::uint64_t gprShlSelfMask = 0;
        std::uint32_t x87ZeroMask = 0;
        std::uint32_t x87UntestMask = 0;
        computeX87StatusMasks(instr.info.mnemonic, x87ZeroMask, x87UntestMask);

        if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            inputIsImmediate = true;
            if (ops[1].imm.value.s == 0)
            {
                rightInputZero = true;
            }
        }

        // Enhanced semantic checks for specific instructions
        switch (instr.info.mnemonic)
        {
            case ZYDIS_MNEMONIC_SUB:
            case ZYDIS_MNEMONIC_CMP:
            case ZYDIS_MNEMONIC_XOR:
            case ZYDIS_MNEMONIC_ANDNPD:
            case ZYDIS_MNEMONIC_ANDNPS:
            case ZYDIS_MNEMONIC_PANDN:
            case ZYDIS_MNEMONIC_PSUBB:
            case ZYDIS_MNEMONIC_PSUBW:
            case ZYDIS_MNEMONIC_PSUBD:
            case ZYDIS_MNEMONIC_PSUBQ:
            case ZYDIS_MNEMONIC_PSUBSB:
            case ZYDIS_MNEMONIC_PSUBSW:
            case ZYDIS_MNEMONIC_PSUBUSB:
            case ZYDIS_MNEMONIC_PSUBUSW:
            case ZYDIS_MNEMONIC_PXOR:
            case ZYDIS_MNEMONIC_XORPS:
            case ZYDIS_MNEMONIC_XORPD:
                resultAlwaysZero = regDestAndSrcSame;
                break;
            case ZYDIS_MNEMONIC_AND:
            case ZYDIS_MNEMONIC_TEST:
                resultAlwaysZero = rightInputZero;
                break;
            case ZYDIS_MNEMONIC_ANDN:
            case ZYDIS_MNEMONIC_VANDNPD:
            case ZYDIS_MNEMONIC_VANDNPS:
            case ZYDIS_MNEMONIC_VPANDN:
            case ZYDIS_MNEMONIC_VPSUBB:
            case ZYDIS_MNEMONIC_VPSUBW:
            case ZYDIS_MNEMONIC_VPSUBD:
            case ZYDIS_MNEMONIC_VPSUBQ:
            case ZYDIS_MNEMONIC_VPSUBSB:
            case ZYDIS_MNEMONIC_VPSUBSW:
            case ZYDIS_MNEMONIC_VPSUBUSB:
            case ZYDIS_MNEMONIC_VPSUBUSW:
            case ZYDIS_MNEMONIC_VPXOR:
            case ZYDIS_MNEMONIC_VXORPS:
            case ZYDIS_MNEMONIC_VXORPD:
                resultAlwaysZero = ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value;
                break;
            case ZYDIS_MNEMONIC_CMPPD:
            case ZYDIS_MNEMONIC_CMPPS:
                if (regDestAndSrcSame && ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    const auto predicate = ops[2].imm.value.u & 0x7;
                    if (predicate == 0x01)
                        resultAlwaysZero = true;
                    else if (predicate == 0x05)
                        resultAlwaysOne = true;
                }
                break;
            case ZYDIS_MNEMONIC_CMPSD:
            case ZYDIS_MNEMONIC_CMPSS:
                if (regDestAndSrcSame && ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    const auto predicate = ops[2].imm.value.u & 0x7;
                    const size_t laneBits = instr.info.mnemonic == ZYDIS_MNEMONIC_CMPSD ? 64 : 32;
                    if (predicate == 0x01)
                        numBitsZero = laneBits;
                    else if (predicate == 0x05)
                        numBitsOne = laneBits;
                }
                break;
            case ZYDIS_MNEMONIC_VCMPPD:
            case ZYDIS_MNEMONIC_VCMPPS:
            case ZYDIS_MNEMONIC_VCMPSD:
            case ZYDIS_MNEMONIC_VCMPSS:
                // VEX compares use a 5-bit predicate (low nibble selects the comparison; bit 4 only
                // toggles signaling). FALSE (0x0B) is unconditionally false, TRUE (0x0F)
                // unconditionally true. For src1==src2 a predicate is always false/true if it is
                // false/true on both the equal and the unordered case.
                if (ops[3].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    const auto lo = ops[3].imm.value.u & 0x0F;
                    const bool selfCmp = ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                        && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].reg.value == ops[2].reg.value;
                    bool allZero = lo == 0x0B;
                    bool allOne = lo == 0x0F;
                    if (selfCmp)
                    {
                        allZero = allZero || lo == 0x01 || lo == 0x0C || lo == 0x0E;
                        allOne = allOne || lo == 0x05 || lo == 0x08 || lo == 0x0A;
                    }
                    const bool scalar = instr.info.mnemonic == ZYDIS_MNEMONIC_VCMPSD
                        || instr.info.mnemonic == ZYDIS_MNEMONIC_VCMPSS;
                    const size_t laneBits = (instr.info.mnemonic == ZYDIS_MNEMONIC_VCMPSD) ? 64 : 32;
                    if (allZero)
                    {
                        if (scalar)
                            numBitsZero = laneBits;
                        else
                            resultAlwaysZero = true;
                    }
                    else if (allOne)
                    {
                        if (scalar)
                            numBitsOne = laneBits;
                        else
                            resultAlwaysOne = true;
                    }
                }
                break;
            case ZYDIS_MNEMONIC_ADD:
            case ZYDIS_MNEMONIC_FADD:
            case ZYDIS_MNEMONIC_XADD:
                firstBitAlwaysZero = regDestAndSrcSame;
                break;
            case ZYDIS_MNEMONIC_PCMPEQB:
            case ZYDIS_MNEMONIC_PCMPEQW:
            case ZYDIS_MNEMONIC_PCMPEQD:
            case ZYDIS_MNEMONIC_PCMPEQQ:
                // Every lane equals itself, so all bytes become 0xFF.
                resultAlwaysOne = regDestAndSrcSame;
                break;
            case ZYDIS_MNEMONIC_PCMPGTB:
            case ZYDIS_MNEMONIC_PCMPGTW:
            case ZYDIS_MNEMONIC_PCMPGTD:
            case ZYDIS_MNEMONIC_PCMPGTQ:
                // x > x is never true, so all lanes become 0.
                resultAlwaysZero = regDestAndSrcSame;
                break;
            case ZYDIS_MNEMONIC_VPCMPEQB:
            case ZYDIS_MNEMONIC_VPCMPEQW:
            case ZYDIS_MNEMONIC_VPCMPEQD:
            case ZYDIS_MNEMONIC_VPCMPEQQ:
                resultAlwaysOne = ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value;
                break;
            case ZYDIS_MNEMONIC_VPCMPGTB:
            case ZYDIS_MNEMONIC_VPCMPGTW:
            case ZYDIS_MNEMONIC_VPCMPGTD:
            case ZYDIS_MNEMONIC_VPCMPGTQ:
                resultAlwaysZero = ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value;
                break;
            case ZYDIS_MNEMONIC_IMUL:
                // dest = src * 0 is zero, which fits, so CF/OF are also cleared.
                if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[2].imm.value.u == 0)
                    resultAlwaysZero = true;
                break;
            case ZYDIS_MNEMONIC_MOV:
                resultAlwaysZero = rightInputZero;
                break;
            case ZYDIS_MNEMONIC_CMPXCHG:
            {
                ZydisRegister acc = ZYDIS_REGISTER_NONE;
                switch (instr.info.operand_width)
                {
                    case 8:
                        acc = ZYDIS_REGISTER_AL;
                        break;
                    case 16:
                        acc = ZYDIS_REGISTER_AX;
                        break;
                    case 32:
                        acc = ZYDIS_REGISTER_EAX;
                        break;
                    case 64:
                        acc = ZYDIS_REGISTER_RAX;
                        break;
                }
                compareAlwaysZero = ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == acc;
                break;
            }
            case ZYDIS_MNEMONIC_COMISD:
            case ZYDIS_MNEMONIC_COMISS:
            case ZYDIS_MNEMONIC_UCOMISD:
            case ZYDIS_MNEMONIC_UCOMISS:
            case ZYDIS_MNEMONIC_VCOMISD:
            case ZYDIS_MNEMONIC_VCOMISS:
            case ZYDIS_MNEMONIC_VUCOMISD:
            case ZYDIS_MNEMONIC_VUCOMISS:
            case ZYDIS_MNEMONIC_FCOMI:
            case ZYDIS_MNEMONIC_FUCOMI:
                zfAlwaysOne = regDestAndSrcSame;
                break;
            case ZYDIS_MNEMONIC_PTEST:
            case ZYDIS_MNEMONIC_VPTEST:
            case ZYDIS_MNEMONIC_VTESTPD:
            case ZYDIS_MNEMONIC_VTESTPS:
                // a AND NOT a == 0, so CF is always set when testing a register against itself.
                cfAlwaysOne = regDestAndSrcSame;
                break;
            case ZYDIS_MNEMONIC_SBB:
                // r - r - CF is 0 or all-ones; either way the low byte (0x00/0xFF) has even parity.
                pfAlwaysOne = regDestAndSrcSame;
                break;
            case ZYDIS_MNEMONIC_SHLD:
            case ZYDIS_MNEMONIC_SHRD:
                // A shift count of 0 performs no operation and leaves the flags untouched, so the
                // flag outputs are not deterministic in the two-run check.
                if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[2].imm.value.u == 0)
                    flagsNotUpdated = true;
                break;
            case ZYDIS_MNEMONIC_SHLX:
                // SHLX of a value by itself is X << (X & mask); the low count bits collapse to the
                // c<<c set, the rest are free. (BMI2 SHLX leaves flags untouched.)
                if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value)
                {
                    gprShlSelfBits = instr.info.operand_width == 64 ? 6 : 5;
                    gprShlSelfMask = selfShlReachableMask(gprShlSelfBits);
                }
                break;
            case ZYDIS_MNEMONIC_DIVPD:
            case ZYDIS_MNEMONIC_DIVSD:
                if (regDestAndSrcSame)
                {
                    laneOneMask = 0x3FF0000000000000ull;
                    laneOneWidth = 64;
                    laneOnePacked = instr.info.mnemonic == ZYDIS_MNEMONIC_DIVPD;
                }
                break;
            case ZYDIS_MNEMONIC_DIVPS:
            case ZYDIS_MNEMONIC_DIVSS:
                if (regDestAndSrcSame)
                {
                    laneOneMask = 0x3F800000ull;
                    laneOneWidth = 32;
                    laneOnePacked = instr.info.mnemonic == ZYDIS_MNEMONIC_DIVPS;
                }
                break;
            case ZYDIS_MNEMONIC_VDIVPD:
            case ZYDIS_MNEMONIC_VDIVSD:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value)
                {
                    laneOneMask = 0x3FF0000000000000ull;
                    laneOneWidth = 64;
                    laneOnePacked = instr.info.mnemonic == ZYDIS_MNEMONIC_VDIVPD;
                }
                break;
            case ZYDIS_MNEMONIC_VDIVPS:
            case ZYDIS_MNEMONIC_VDIVSS:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value)
                {
                    laneOneMask = 0x3F800000ull;
                    laneOneWidth = 32;
                    laneOnePacked = instr.info.mnemonic == ZYDIS_MNEMONIC_VDIVPS;
                }
                break;
            case ZYDIS_MNEMONIC_DPPD:
                if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    const auto imm = ops[2].imm.value.u;
                    const bool noProducts = (imm & 0x30) == 0;
                    laneZeroWidth = 64;
                    if (noProducts || (imm & 0x1) == 0)
                        laneZeroMask |= 0x1;
                    if (noProducts || (imm & 0x2) == 0)
                        laneZeroMask |= 0x2;
                }
                break;
            case ZYDIS_MNEMONIC_VDPPD:
                if (ops[3].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    const auto imm = ops[3].imm.value.u;
                    const bool noProducts = (imm & 0x30) == 0;
                    laneZeroWidth = 64;
                    if (noProducts || (imm & 0x1) == 0)
                        laneZeroMask |= 0x1;
                    if (noProducts || (imm & 0x2) == 0)
                        laneZeroMask |= 0x2;
                }
                break;
            case ZYDIS_MNEMONIC_DPPS:
                if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    const auto imm = ops[2].imm.value.u;
                    const bool noProducts = (imm & 0xF0) == 0;
                    laneZeroWidth = 32;
                    for (unsigned l = 0; l < 4; ++l)
                        if (noProducts || (imm & (1u << l)) == 0)
                            laneZeroMask |= (1u << l);
                }
                break;
            case ZYDIS_MNEMONIC_VDPPS:
                if (ops[3].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    const auto imm = ops[3].imm.value.u;
                    const bool noProducts = (imm & 0xF0) == 0;
                    laneZeroWidth = 32;
                    for (unsigned l = 0; l < 4; ++l)
                        if (noProducts || (imm & (1u << l)) == 0)
                            laneZeroMask |= (1u << l);
                }
                break;
            case ZYDIS_MNEMONIC_INSERTPS:
                // imm bits 0-3 (zmask) zero the corresponding 32-bit result lanes.
                if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneZeroWidth = 32;
                    laneZeroMask = ops[2].imm.value.u & 0xF;
                }
                break;
            case ZYDIS_MNEMONIC_VINSERTPS:
                if (ops[3].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneZeroWidth = 32;
                    laneZeroMask = ops[3].imm.value.u & 0xF;
                }
                break;
            case ZYDIS_MNEMONIC_VCVTPH2PS:
                // Half-precision has a 10-bit mantissa; widening to single leaves the low 13
                // mantissa bits of every 32-bit lane 0.
                laneLowZeroWidth = 32;
                laneLowZeroBits = 13;
                break;
            // Shift-by-immediate zeros the vacated bits in each lane: PSLL the low `imm` bits,
            // PSRL the high `imm` bits (a count >= lane width zeros the whole lane).
            // Shift-by-immediate zeros vacated bits per lane; shift-by-self (count register ==
            // data register) couples count and data: see the register loop for the structure.
            case ZYDIS_MNEMONIC_PSLLW:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneLowZeroWidth = 16;
                    laneLowZeroBits = std::min<unsigned>(static_cast<unsigned>(ops[1].imm.value.u), 16);
                }
                else if (regDestAndSrcSame)
                {
                    shiftSelfLaneWidth = 16;
                    shiftSelfShl = true;
                    shiftSelfMask = selfShlReachableMask(16);
                }
                break;
            case ZYDIS_MNEMONIC_PSLLD:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneLowZeroWidth = 32;
                    laneLowZeroBits = std::min<unsigned>(static_cast<unsigned>(ops[1].imm.value.u), 32);
                }
                else if (regDestAndSrcSame)
                {
                    shiftSelfLaneWidth = 32;
                    shiftSelfShl = true;
                    shiftSelfMask = selfShlReachableMask(32);
                }
                break;
            case ZYDIS_MNEMONIC_PSLLQ:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneLowZeroWidth = 64;
                    laneLowZeroBits = std::min<unsigned>(static_cast<unsigned>(ops[1].imm.value.u), 64);
                }
                else if (regDestAndSrcSame)
                {
                    shiftSelfLaneWidth = 64;
                    shiftSelfShl = true;
                    shiftSelfMask = selfShlReachableMask(64);
                }
                break;
            case ZYDIS_MNEMONIC_PSRLW:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneKeepWidth = 16;
                    laneKeepBits = 16 - std::min<unsigned>(static_cast<unsigned>(ops[1].imm.value.u), 16);
                }
                else if (regDestAndSrcSame)
                {
                    shiftSelfLaneWidth = 16;
                }
                break;
            case ZYDIS_MNEMONIC_PSRLD:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneKeepWidth = 32;
                    laneKeepBits = 32 - std::min<unsigned>(static_cast<unsigned>(ops[1].imm.value.u), 32);
                }
                else if (regDestAndSrcSame)
                {
                    shiftSelfLaneWidth = 32;
                }
                break;
            case ZYDIS_MNEMONIC_PSRLQ:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneKeepWidth = 64;
                    laneKeepBits = 64 - std::min<unsigned>(static_cast<unsigned>(ops[1].imm.value.u), 64);
                }
                else if (regDestAndSrcSame)
                {
                    shiftSelfLaneWidth = 64;
                }
                break;
            // Whole-register byte shift: PSLLDQ zeros the low imm bytes, PSRLDQ the high imm bytes.
            case ZYDIS_MNEMONIC_PSLLDQ:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneLowZeroWidth = 128;
                    laneLowZeroBits = std::min<unsigned>(static_cast<unsigned>(ops[1].imm.value.u) * 8, 128);
                }
                break;
            case ZYDIS_MNEMONIC_VPSLLDQ:
                if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneLowZeroWidth = 128;
                    laneLowZeroBits = std::min<unsigned>(static_cast<unsigned>(ops[2].imm.value.u) * 8, 128);
                }
                break;
            case ZYDIS_MNEMONIC_PSRLDQ:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneKeepWidth = 128;
                    laneKeepBits = 128 - std::min<unsigned>(static_cast<unsigned>(ops[1].imm.value.u) * 8, 128);
                }
                break;
            case ZYDIS_MNEMONIC_VPSRLDQ:
                if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneKeepWidth = 128;
                    laneKeepBits = 128 - std::min<unsigned>(static_cast<unsigned>(ops[2].imm.value.u) * 8, 128);
                }
                break;
            // Arithmetic shift right by self: the count lanes shift away to 0 (count is positive).
            case ZYDIS_MNEMONIC_PSRAW:
                if (regDestAndSrcSame)
                    shiftSelfLaneWidth = 16;
                break;
            case ZYDIS_MNEMONIC_PSRAD:
                if (regDestAndSrcSame)
                    shiftSelfLaneWidth = 32;
                break;
            // VEX variable shifts apply a per-lane count; self means each lane shifts by itself.
            case ZYDIS_MNEMONIC_VPSLLVD:
            case ZYDIS_MNEMONIC_VPSLLVQ:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value)
                {
                    shiftSelfLaneWidth = instr.info.mnemonic == ZYDIS_MNEMONIC_VPSLLVD ? 32 : 64;
                    shiftSelfShl = true;
                    shiftSelfAllLanes = true;
                    shiftSelfMask = selfShlReachableMask(shiftSelfLaneWidth);
                }
                break;
            case ZYDIS_MNEMONIC_VPSRLVD:
            case ZYDIS_MNEMONIC_VPSRLVQ:
                // Each lane >> itself is 0.
                if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value)
                    resultAlwaysZero = true;
                break;
            // VEX scalar shifts: count/imm is operand 2; self is ops[1] == ops[2].
            case ZYDIS_MNEMONIC_VPSLLW:
            case ZYDIS_MNEMONIC_VPSLLD:
            case ZYDIS_MNEMONIC_VPSLLQ:
            {
                const unsigned w = instr.info.mnemonic == ZYDIS_MNEMONIC_VPSLLW
                    ? 16
                    : (instr.info.mnemonic == ZYDIS_MNEMONIC_VPSLLD ? 32 : 64);
                if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneLowZeroWidth = w;
                    laneLowZeroBits = std::min<unsigned>(static_cast<unsigned>(ops[2].imm.value.u), w);
                }
                else if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value)
                {
                    shiftSelfLaneWidth = w;
                    shiftSelfShl = true;
                    shiftSelfMask = selfShlReachableMask(w);
                }
                break;
            }
            case ZYDIS_MNEMONIC_VPSRLW:
            case ZYDIS_MNEMONIC_VPSRLD:
            case ZYDIS_MNEMONIC_VPSRLQ:
            {
                const unsigned w = instr.info.mnemonic == ZYDIS_MNEMONIC_VPSRLW
                    ? 16
                    : (instr.info.mnemonic == ZYDIS_MNEMONIC_VPSRLD ? 32 : 64);
                if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    laneKeepWidth = w;
                    laneKeepBits = w - std::min<unsigned>(static_cast<unsigned>(ops[2].imm.value.u), w);
                }
                else if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value)
                {
                    shiftSelfLaneWidth = w;
                }
                break;
            }
            case ZYDIS_MNEMONIC_VPSRAW:
            case ZYDIS_MNEMONIC_VPSRAD:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value)
                    shiftSelfLaneWidth = instr.info.mnemonic == ZYDIS_MNEMONIC_VPSRAW ? 16 : 32;
                break;
            // PMOVZX zero-extends each source element into a wider lane; the bits above the
            // source element width are 0 in every destination lane.
            case ZYDIS_MNEMONIC_PMOVZXBW:
            case ZYDIS_MNEMONIC_VPMOVZXBW:
                laneKeepWidth = 16;
                laneKeepBits = 8;
                break;
            case ZYDIS_MNEMONIC_PMOVZXBD:
            case ZYDIS_MNEMONIC_VPMOVZXBD:
                laneKeepWidth = 32;
                laneKeepBits = 8;
                break;
            case ZYDIS_MNEMONIC_PMOVZXBQ:
            case ZYDIS_MNEMONIC_VPMOVZXBQ:
                laneKeepWidth = 64;
                laneKeepBits = 8;
                break;
            case ZYDIS_MNEMONIC_PMOVZXWD:
            case ZYDIS_MNEMONIC_VPMOVZXWD:
                laneKeepWidth = 32;
                laneKeepBits = 16;
                break;
            case ZYDIS_MNEMONIC_PMOVZXWQ:
            case ZYDIS_MNEMONIC_VPMOVZXWQ:
                laneKeepWidth = 64;
                laneKeepBits = 16;
                break;
            case ZYDIS_MNEMONIC_PMOVZXDQ:
            case ZYDIS_MNEMONIC_VPMOVZXDQ:
                laneKeepWidth = 64;
                laneKeepBits = 32;
                break;
            case ZYDIS_MNEMONIC_PSADBW:
                // Each 64-bit lane is a sum of 8 absolute byte differences (<= 2040 < 2^11);
                // against itself every difference is 0, so the whole result is 0.
                laneKeepWidth = 64;
                laneKeepBits = 11;
                if (regDestAndSrcSame)
                    resultAlwaysZero = true;
                break;
            case ZYDIS_MNEMONIC_VPSADBW:
                laneKeepWidth = 64;
                laneKeepBits = 11;
                if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value)
                    resultAlwaysZero = true;
                break;
            // Packed self low-multiply squares each lane; bit 1 of every lane is 0 (square mod 4).
            case ZYDIS_MNEMONIC_PMULLW:
                if (regDestAndSrcSame)
                    selfSquareLaneWidth = 16;
                break;
            case ZYDIS_MNEMONIC_PMULLD:
                if (regDestAndSrcSame)
                    selfSquareLaneWidth = 32;
                break;
            case ZYDIS_MNEMONIC_VPMULLW:
            case ZYDIS_MNEMONIC_VPMULLD:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value)
                    selfSquareLaneWidth = instr.info.mnemonic == ZYDIS_MNEMONIC_VPMULLW ? 16 : 32;
                break;
            // Packed self-add doubles each lane, so the low bit of every lane is 0.
            case ZYDIS_MNEMONIC_PADDB:
                if (regDestAndSrcSame)
                    selfAddLaneWidth = 8;
                break;
            case ZYDIS_MNEMONIC_PADDW:
                if (regDestAndSrcSame)
                    selfAddLaneWidth = 16;
                break;
            case ZYDIS_MNEMONIC_PADDD:
                if (regDestAndSrcSame)
                    selfAddLaneWidth = 32;
                break;
            case ZYDIS_MNEMONIC_PADDQ:
                if (regDestAndSrcSame)
                    selfAddLaneWidth = 64;
                break;
            case ZYDIS_MNEMONIC_VPADDB:
            case ZYDIS_MNEMONIC_VPADDW:
            case ZYDIS_MNEMONIC_VPADDD:
            case ZYDIS_MNEMONIC_VPADDQ:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value)
                {
                    switch (instr.info.mnemonic)
                    {
                        case ZYDIS_MNEMONIC_VPADDB:
                            selfAddLaneWidth = 8;
                            break;
                        case ZYDIS_MNEMONIC_VPADDW:
                            selfAddLaneWidth = 16;
                            break;
                        case ZYDIS_MNEMONIC_VPADDD:
                            selfAddLaneWidth = 32;
                            break;
                        case ZYDIS_MNEMONIC_VPADDQ:
                            selfAddLaneWidth = 64;
                            break;
                        default:
                            break;
                    }
                }
                break;
            case ZYDIS_MNEMONIC_MPSADBW:
                // Self-SAD: the output word whose src1 window aligns with the src2 block is all
                // zeros. Verified empirically: that word index is 4*(imm[1:0] - imm[2]) in [0,7].
                if (regDestAndSrcSame && ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    const auto imm = ops[2].imm.value.u;
                    const int zeroWord = 4 * (static_cast<int>(imm & 3) - static_cast<int>((imm >> 2) & 1));
                    if (zeroWord >= 0 && zeroWord <= 7)
                    {
                        laneZeroWidth = 16;
                        laneZeroMask = 1u << zeroWord;
                    }
                }
                break;
            case ZYDIS_MNEMONIC_VMPSADBW:
                if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value && ops[3].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    const auto imm = ops[3].imm.value.u;
                    const int zeroWord = 4 * (static_cast<int>(imm & 3) - static_cast<int>((imm >> 2) & 1));
                    if (zeroWord >= 0 && zeroWord <= 7)
                    {
                        laneZeroWidth = 16;
                        laneZeroMask = 1u << zeroWord;
                    }
                }
                break;
        }

        bool fpConvPacked = true;
        const unsigned fpConvZeroLow = fpConvZeroLowPerLane(instr, fpConvPacked);

        bool alwaysFaults = false;
        if (instr.info.mnemonic == ZYDIS_MNEMONIC_DIV || instr.info.mnemonic == ZYDIS_MNEMONIC_IDIV)
        {
            ZydisRegister highReg = ZYDIS_REGISTER_NONE;
            switch (instr.info.operand_width)
            {
                case 8:
                    highReg = ZYDIS_REGISTER_AH;
                    break;
                case 16:
                    highReg = ZYDIS_REGISTER_DX;
                    break;
                case 32:
                    highReg = ZYDIS_REGISTER_EDX;
                    break;
                case 64:
                    highReg = ZYDIS_REGISTER_RDX;
                    break;
            }
            if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == highReg)
                alwaysFaults = true;
        }

        // Generate test matrix for registers
        for (auto& regModified : regsModified)
        {
            if (alwaysFaults)
                break;

            const auto regSize = ZydisRegisterGetWidth(instr.info.machine_mode, regModified);
            const auto knownReg = computeKnownReg(instr, regSize);

            auto maxBits = regSize;
            switch (instr.info.mnemonic)
            {
                case ZYDIS_MNEMONIC_SETB:
                case ZYDIS_MNEMONIC_SETBE:
                case ZYDIS_MNEMONIC_SETL:
                case ZYDIS_MNEMONIC_SETLE:
                case ZYDIS_MNEMONIC_SETNB:
                case ZYDIS_MNEMONIC_SETNBE:
                case ZYDIS_MNEMONIC_SETNL:
                case ZYDIS_MNEMONIC_SETNLE:
                case ZYDIS_MNEMONIC_SETNO:
                case ZYDIS_MNEMONIC_SETNP:
                case ZYDIS_MNEMONIC_SETNS:
                case ZYDIS_MNEMONIC_SETNZ:
                case ZYDIS_MNEMONIC_SETO:
                case ZYDIS_MNEMONIC_SETP:
                case ZYDIS_MNEMONIC_SETS:
                case ZYDIS_MNEMONIC_SETZ:
                    maxBits = 1;
                    break;
                case ZYDIS_MNEMONIC_LEA:
                    maxBits = instr.info.address_width;
                    break;
                case ZYDIS_MNEMONIC_BSWAP:
                    resultAlwaysZero = regSize <= 16;
                    break;
                case ZYDIS_MNEMONIC_CVTPD2DQ:
                case ZYDIS_MNEMONIC_VCVTPD2DQ:
                case ZYDIS_MNEMONIC_CVTTPD2DQ:
                case ZYDIS_MNEMONIC_VCVTTPD2DQ:
                case ZYDIS_MNEMONIC_CVTPD2PS:
                case ZYDIS_MNEMONIC_VCVTPD2PS:
                case ZYDIS_MNEMONIC_VCVTPS2PH:
                    maxBits = ops[1].size / 2;
                    break;
                case ZYDIS_MNEMONIC_MOVD:
                case ZYDIS_MNEMONIC_VMOVD:
                    // Writing an XMM destination zero-extends to 128 bits (low 32 hold the value).
                    maxBits = 32;
                    break;
                case ZYDIS_MNEMONIC_VMOVQ:
                    maxBits = 64;
                    break;
                case ZYDIS_MNEMONIC_PEXTRB:
                case ZYDIS_MNEMONIC_VPEXTRB:
                    // Extracts a single byte/word into a GPR, zero-extended.
                    maxBits = 8;
                    break;
                case ZYDIS_MNEMONIC_PEXTRW:
                case ZYDIS_MNEMONIC_VPEXTRW:
                    maxBits = 16;
                    break;
                case ZYDIS_MNEMONIC_PHMINPOSUW:
                case ZYDIS_MNEMONIC_VPHMINPOSUW:
                    // bits 0-15 hold the minimum word, bits 16-18 its index (0-7), rest 0.
                    maxBits = 19;
                    break;
                case ZYDIS_MNEMONIC_MOVQ:
                    maxBits = 64;
                    break;
                case ZYDIS_MNEMONIC_MOVMSKPD:
                case ZYDIS_MNEMONIC_VMOVMSKPD:
                    // One sign bit per packed double; the rest of the GPR is cleared.
                    maxBits = ops[1].size / 64;
                    break;
                case ZYDIS_MNEMONIC_MOVMSKPS:
                case ZYDIS_MNEMONIC_VMOVMSKPS:
                    maxBits = ops[1].size / 32;
                    break;
                case ZYDIS_MNEMONIC_PMOVMSKB:
                case ZYDIS_MNEMONIC_VPMOVMSKB:
                    maxBits = ops[1].size / 8;
                    break;
                case ZYDIS_MNEMONIC_PCLMULQDQ:
                case ZYDIS_MNEMONIC_VPCLMULQDQ:
                    // Carryless product of two 64-bit values reaches at most bit 126.
                    maxBits = 127;
                    break;
                case ZYDIS_MNEMONIC_PCMPESTRI:
                case ZYDIS_MNEMONIC_PCMPISTRI:
                case ZYDIS_MNEMONIC_VPCMPESTRI:
                case ZYDIS_MNEMONIC_VPCMPISTRI:
                    // Index result into 16 byte (or 8 word) elements is at most 16.
                    if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        maxBits = (ops[2].imm.value.u & 1) ? 4 : 5;
                    break;
                case ZYDIS_MNEMONIC_PCMPESTRM:
                case ZYDIS_MNEMONIC_PCMPISTRM:
                case ZYDIS_MNEMONIC_VPCMPESTRM:
                case ZYDIS_MNEMONIC_VPCMPISTRM:
                    // imm[6]=0 produces a bit mask in the low 16 (byte) or 8 (word) bits, rest 0.
                    if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ((ops[2].imm.value.u >> 6) & 1) == 0)
                        maxBits = (ops[2].imm.value.u & 1) ? 8 : 16;
                    break;
                case ZYDIS_MNEMONIC_PALIGNR:
                    // Concatenate dest:src, shift right imm bytes, keep low 16; bytes shifted in
                    // from beyond the 32-byte concatenation are 0.
                    if (ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        maxBits = static_cast<unsigned>(std::clamp(32 - static_cast<int>(ops[2].imm.value.u), 0, 16)) * 8;
                    break;
                case ZYDIS_MNEMONIC_VPALIGNR:
                    if (ops[3].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        maxBits = static_cast<unsigned>(std::clamp(32 - static_cast<int>(ops[3].imm.value.u), 0, 16)) * 8;
                    break;
            }

            for (std::uint16_t bitPos = 0; bitPos < regSize; ++bitPos)
            {
                bool testZero = testRegZero;
                bool testOne = bitPos >= numBitsZero && !resultAlwaysZero && bitPos < maxBits;

                if (instr.info.mnemonic == ZYDIS_MNEMONIC_MOV && inputIsImmediate)
                {
                    // We know the input value so we will expect those bits.
                    testZero = (ops[1].imm.value.u & (1ULL << bitPos)) == 0;
                    testOne = (ops[1].imm.value.u & (1ULL << bitPos)) != 0;
                }
                else if (instr.info.mnemonic == ZYDIS_MNEMONIC_OR && inputIsImmediate)
                {
                    // If the input bit is not zero then the output bit will never be zero.
                    testZero = (ops[1].imm.value.u & (1ULL << bitPos)) == 0;
                }
                else if (instr.info.mnemonic == ZYDIS_MNEMONIC_AND && inputIsImmediate)
                {
                    // If the input bit is zero then the output bit will never be one.
                    testOne = (ops[1].imm.value.u & (1ULL << bitPos)) != 0;
                }
                else if (instr.info.mnemonic == ZYDIS_MNEMONIC_BTR && inputIsImmediate)
                {
                    // BTR is just reg[bit] = 0
                    testOne = ((ops[1].imm.value.u % instr.info.operand_width) != bitPos);
                }

                if (knownReg.knownOne(bitPos))
                    testZero = false;
                if (knownReg.knownZero(bitPos))
                    testOne = false;

                if (resultAlwaysOne || bitPos < numBitsOne)
                    testZero = false;

                if (laneOneMask != 0 && (laneOnePacked || bitPos < laneOneWidth)
                    && ((laneOneMask >> (bitPos % laneOneWidth)) & 1ull) != 0)
                    testZero = false;

                if (laneZeroWidth != 0 && (laneZeroMask & (1u << (bitPos / laneZeroWidth))) != 0)
                    testOne = false;

                if (selfAddLaneWidth != 0 && (bitPos % selfAddLaneWidth) == 0)
                    testOne = false;

                if (selfSquareLaneWidth != 0 && (bitPos % selfSquareLaneWidth) == 1)
                    testOne = false;

                if (laneKeepWidth != 0 && (bitPos % laneKeepWidth) >= laneKeepBits)
                    testOne = false;

                if (laneLowZeroWidth != 0 && (bitPos % laneLowZeroWidth) < laneLowZeroBits)
                    testOne = false;

                // Shift-by-self: the lanes overlapping the count are constrained. For a scalar
                // count (low 64 bits) only lanes within that qword are affected; VEX variable
                // shifts couple every lane. A left shift makes the count's low lane the sparse
                // c<<c set and the rest of its count lanes 0; a right shift zeros all count lanes.
                if (shiftSelfLaneWidth != 0)
                {
                    const unsigned lane = bitPos / shiftSelfLaneWidth;
                    const unsigned posInLane = bitPos % shiftSelfLaneWidth;
                    const unsigned numCountLanes = shiftSelfAllLanes ? (128 / shiftSelfLaneWidth) : (64 / shiftSelfLaneWidth);
                    if (lane < numCountLanes)
                    {
                        if (!shiftSelfShl)
                            testOne = false;
                        else if (shiftSelfAllLanes || lane == 0)
                        {
                            if (((shiftSelfMask >> posInLane) & 1ull) == 0)
                                testOne = false;
                        }
                        else
                            testOne = false;
                    }
                }

                if (gprShlSelfBits != 0 && bitPos < gprShlSelfBits && ((gprShlSelfMask >> bitPos) & 1ull) == 0)
                    testOne = false;

                // Carryless self-square (same source qword for both factors) cancels every cross
                // term, leaving zeros in all odd bit positions.
                if (instr.info.mnemonic == ZYDIS_MNEMONIC_PCLMULQDQ && regDestAndSrcSame
                    && ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                    && (ops[2].imm.value.u & 1) == ((ops[2].imm.value.u >> 4) & 1) && (bitPos % 2) == 1)
                    testOne = false;
                if (instr.info.mnemonic == ZYDIS_MNEMONIC_VPCLMULQDQ
                    && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ops[1].reg.value == ops[2].reg.value && ops[3].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                    && (ops[3].imm.value.u & 1) == ((ops[3].imm.value.u >> 4) & 1) && (bitPos % 2) == 1)
                    testOne = false;

                if (fpConvZeroLow > 0 && (fpConvPacked ? (bitPos % 64) : bitPos) < fpConvZeroLow)
                    testOne = false;

                if (regModified == ZYDIS_REGISTER_X87STATUS)
                {
                    if (((x87UntestMask >> bitPos) & 1) != 0)
                    {
                        testZero = false;
                        testOne = false;
                    }
                    else if (((x87ZeroMask >> bitPos) & 1) != 0)
                        testOne = false;
                }

                // FABS clears the sign bit (bit 79) of the 80-bit result; |x| is never negative.
                if (instr.info.mnemonic == ZYDIS_MNEMONIC_FABS && regModified == ZYDIS_REGISTER_ST0 && bitPos == 79)
                    testOne = false;

                // Comparing ST0 with itself is always equal (or unordered if NaN); both set C3=1.
                if (regModified == ZYDIS_REGISTER_X87STATUS && bitPos == 14 && regDestAndSrcSame
                    && (instr.info.mnemonic == ZYDIS_MNEMONIC_FCOM || instr.info.mnemonic == ZYDIS_MNEMONIC_FUCOM))
                    testZero = false;

                // cos(x) is never 0 or denormal, and invalid/out-of-range inputs give the
                // indefinite QNaN; every possible result has the integer bit (63) set.
                if (instr.info.mnemonic == ZYDIS_MNEMONIC_FCOS && regModified == ZYDIS_REGISTER_ST0 && bitPos == 63)
                    testZero = false;

                // ST0/ST0 is always 1.0 (exact) or a NaN; both share the integer bit (63) and
                // the low exponent bits (64-77), and the exact/NaN result never rounds (C1=0).
                const bool fdivSelf = regDestAndSrcSame
                    && (instr.info.mnemonic == ZYDIS_MNEMONIC_FDIV || instr.info.mnemonic == ZYDIS_MNEMONIC_FDIVR);
                if (fdivSelf && regModified == ZYDIS_REGISTER_ST0 && (bitPos == 63 || (bitPos >= 64 && bitPos <= 77)))
                    testZero = false;

                // ST0-ST0 is always +0.0 (exact) or a NaN; like the self-divide, the result
                // never rounds, so C1 is 0 (but {0.0, NaN} shares no fixed data bits).
                const bool fsubSelf = regDestAndSrcSame
                    && (instr.info.mnemonic == ZYDIS_MNEMONIC_FSUB || instr.info.mnemonic == ZYDIS_MNEMONIC_FSUBR);
                if ((fdivSelf || fsubSelf) && regModified == ZYDIS_REGISTER_X87STATUS && bitPos == 9)
                    testOne = false;

                // FNSTSW copies the status word into AX; ES(7), TOP(11-13) and B(15) are
                // always 0 here, just as in the status word itself.
                if (instr.info.mnemonic == ZYDIS_MNEMONIC_FNSTSW && regModified == ZYDIS_REGISTER_AX
                    && ((0xB880u >> bitPos) & 1) != 0)
                    testOne = false;

                // MPSADBW words are sums of 4 absolute byte differences (<= 1020 < 1024), so the
                // top 6 bits of each 16-bit lane are always 0.
                if ((instr.info.mnemonic == ZYDIS_MNEMONIC_MPSADBW || instr.info.mnemonic == ZYDIS_MNEMONIC_VMPSADBW)
                    && (bitPos % 16) >= 10)
                    testOne = false;

                // Self-compare PCMP*STRI in an "equal" mode (equal-any/each/ordered) with LSB
                // ordering and positive polarity gives index 0 (match at position 0) or maxlen
                // (zero-length input); only the maxlen bit (4 for bytes, 3 for words) can be set.
                if ((instr.info.mnemonic == ZYDIS_MNEMONIC_PCMPESTRI || instr.info.mnemonic == ZYDIS_MNEMONIC_PCMPISTRI
                        || instr.info.mnemonic == ZYDIS_MNEMONIC_VPCMPESTRI
                        || instr.info.mnemonic == ZYDIS_MNEMONIC_VPCMPISTRI)
                    && regDestAndSrcSame && ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    const auto imm = ops[2].imm.value.u;
                    const bool lsb = ((imm >> 6) & 1) == 0;
                    const bool notRanges = ((imm >> 2) & 3) != 1;
                    const bool positive = ((imm >> 4) & 3) == 0;
                    if (lsb && notRanges && positive && bitPos < ((imm & 1) ? 3u : 4u))
                        testOne = false;
                }

                // LAHF loads AH from the EFLAGS low byte: bit 1 is reserved-1, bits 3 and 5
                // are reserved-0.
                if (instr.info.mnemonic == ZYDIS_MNEMONIC_LAHF && regModified == ZYDIS_REGISTER_AH)
                {
                    if (((0x28u >> bitPos) & 1) != 0)
                        testOne = false;
                    if (bitPos == 1)
                        testZero = false;
                }

                // PMULDQ/PMULUDQ self-multiply each 64-bit lane by itself, giving a perfect
                // square: bit 1 of every lane is 0, and signed PMULDQ stays <= 2^62 so the
                // lane's top bit (63) is 0 as well.
                {
                    const bool pmulSelf = (regDestAndSrcSame
                                           && (instr.info.mnemonic == ZYDIS_MNEMONIC_PMULDQ
                                               || instr.info.mnemonic == ZYDIS_MNEMONIC_PMULUDQ))
                        || ((instr.info.mnemonic == ZYDIS_MNEMONIC_VPMULDQ || instr.info.mnemonic == ZYDIS_MNEMONIC_VPMULUDQ)
                            && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                            && ops[1].reg.value == ops[2].reg.value);
                    const bool pmulSigned = instr.info.mnemonic == ZYDIS_MNEMONIC_PMULDQ
                        || instr.info.mnemonic == ZYDIS_MNEMONIC_VPMULDQ;
                    if (pmulSelf && (bitPos % 64) == 1)
                        testOne = false;
                    if (pmulSelf && pmulSigned && (bitPos % 64) == 63)
                        testOne = false;
                }

                // PMULHW self-squares each signed word and keeps the high 16 bits; a square is
                // <= 2^30, so its high word is <= 2^14 and bit 15 of every word lane is 0.
                if ((bitPos % 16) == 15
                    && ((regDestAndSrcSame && instr.info.mnemonic == ZYDIS_MNEMONIC_PMULHW)
                        || (instr.info.mnemonic == ZYDIS_MNEMONIC_VPMULHW && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                            && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].reg.value == ops[2].reg.value)))
                    testOne = false;

                // MULX multiplies the explicit source by the implicit (R|E)DX; when the source
                // is that same DX register the low result is a perfect square, so bit 1 is 0.
                if (instr.info.mnemonic == ZYDIS_MNEMONIC_MULX && ops[2].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && ZydisRegisterGetLargestEnclosing(instr.info.machine_mode, ops[2].reg.value) == ZYDIS_REGISTER_RDX
                    && regModified == ops[1].reg.value && bitPos == 1)
                    testOne = false;

                // 1-operand IMUL of the accumulator by itself is a non-negative square below
                // 2^(2N-2), so the top bit of the full 2N-bit product is always 0.
                if (instr.info.mnemonic == ZYDIS_MNEMONIC_IMUL && regDestAndSrcSame)
                {
                    if (instr.info.operand_width == 8 && regModified == ZYDIS_REGISTER_AX && bitPos == 15)
                        testOne = false;
                    else if (regModified == ZYDIS_REGISTER_DX && bitPos == 15)
                        testOne = false;
                    else if (regModified == ZYDIS_REGISTER_EDX && bitPos == 31)
                        testOne = false;
                    else if (regModified == ZYDIS_REGISTER_RDX && bitPos == 63)
                        testOne = false;
                }

                // Expect 0 if possible.
                if (testZero)
                {
                    matrix.push_back({ ExceptionType::None, regModified, bitPos, 0 });
                }

                if (bitPos == 0 && firstBitAlwaysZero)
                    testOne = false;

                // Expect 1 if possible.
                if (testOne)
                {
                    matrix.push_back({ ExceptionType::None, regModified, bitPos, 1 });
                }
            }
        }

        // IMUL by 0 or 1 always fits the destination, so CF and OF are cleared.
        const bool mulCannotOverflow = instr.info.mnemonic == ZYDIS_MNEMONIC_IMUL && ops[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
            && (ops[2].imm.value.u == 0 || ops[2].imm.value.u == 1);

        // Generate test matrix for flags
        for (std::size_t i = 0; i < 32 && !alwaysFaults; ++i)
        {
            const auto flag = 1U << i;

            if (!inputIsImmediate)
            {
                if ((flagsModified & flag) != 0)
                {
                    bool testFlagZero = true;
                    bool testFlagOne = true;

                    const bool zeroResult = resultAlwaysZero || compareAlwaysZero;

                    // Additional checks for specific flags based on instruction type.
                    if (flag == ZYDIS_CPUFLAG_ZF)
                    {
                        testFlagZero = !zeroResult && !zfAlwaysOne;
                    }
                    if (flag == ZYDIS_CPUFLAG_CF)
                    {
                        testFlagOne = !zeroResult && !rightInputZero && !mulCannotOverflow;
                        if (cfAlwaysOne)
                        {
                            testFlagOne = true;
                            testFlagZero = false;
                        }
                    }
                    if (flag == ZYDIS_CPUFLAG_OF)
                    {
                        testFlagOne = !regDestAndSrcSame && !rightInputZero && !zeroResult && !mulCannotOverflow;
                    }
                    if (flag == ZYDIS_CPUFLAG_PF)
                    {
                        testFlagZero = !zeroResult && !pfAlwaysOne;
                    }
                    if (flag == ZYDIS_CPUFLAG_AF)
                    {
                        testFlagOne = !zeroResult && !rightInputZero;
                    }
                    if (flag == ZYDIS_CPUFLAG_SF)
                    {
                        testFlagOne = !zeroResult;
                    }

                    if (flagsNotUpdated)
                    {
                        testFlagZero = false;
                        testFlagOne = false;
                    }

                    // Expect 0 if possible.
                    if (testFlagZero)
                    {
                        matrix.push_back({ ExceptionType::None, ZYDIS_REGISTER_FLAGS, static_cast<std::uint16_t>(i), 0 });
                    }

                    // Expect 1 if possible.
                    if (testFlagOne)
                    {
                        matrix.push_back({ ExceptionType::None, ZYDIS_REGISTER_FLAGS, static_cast<std::uint16_t>(i), 1 });
                    }
                }
            }

            if ((flagsSet0 & flag) != 0)
            {
                matrix.push_back({ ExceptionType::None, ZYDIS_REGISTER_FLAGS, static_cast<std::uint16_t>(i), 0 });
            }

            if ((flagsSet1 & flag) != 0)
            {
                matrix.push_back({ ExceptionType::None, ZYDIS_REGISTER_FLAGS, static_cast<std::uint16_t>(i), 1 });
            }
        }

        // Generate test matrix for exceptions.
        const auto exceptions = getExceptions(instr);
        for (const auto& exception : exceptions)
        {
            matrix.push_back({ exception, ZYDIS_REGISTER_NONE, 0, 0 });
        }

        return matrix;
    }

} // namespace x86Tester::Generator
