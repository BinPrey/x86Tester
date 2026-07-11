#include "basegenerator.hpp"
#include "generator.hpp"
#include "genshared.hpp"

#include <Zydis/Disassembler.h>
#include <Zydis/Encoder.h>
#include <x86Tester/cpuid.hpp>
extern "C" {
#include <Zydis/Internal/EncoderData.h>
#include <Zydis/Internal/SharedData.h>
}

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fmt/format.h>
#ifdef _WIN32
#    include <intrin.h>
#else
#    include <cpuid.h>
#endif
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <sfl/small_flat_set.hpp>
#include <sfl/static_flat_map.hpp>
#include <sfl/static_flat_set.hpp>
#include <sfl/static_vector.hpp>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <x86Tester/execution.hpp>
#include <x86Tester/inputgenerator.hpp>
#include <x86Tester/logging.hpp>
#include <x86Tester/parallel.hpp>

namespace x86Tester::Generator
{
    namespace Generators
    {
        namespace Detail
        {
            struct SegRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_ES, ZYDIS_REGISTER_CS, ZYDIS_REGISTER_SS,
                    ZYDIS_REGISTER_DS, ZYDIS_REGISTER_FS, ZYDIS_REGISTER_GS,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_CS,
                    ZYDIS_REGISTER_DS,
                };
            };

            struct Gp8Regs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_AL,   ZYDIS_REGISTER_CL,   ZYDIS_REGISTER_DL,   ZYDIS_REGISTER_BL,   ZYDIS_REGISTER_AH,
                    ZYDIS_REGISTER_CH,   ZYDIS_REGISTER_DH,   ZYDIS_REGISTER_BH,   ZYDIS_REGISTER_SPL,  ZYDIS_REGISTER_BPL,
                    ZYDIS_REGISTER_SIL,  ZYDIS_REGISTER_DIL,  ZYDIS_REGISTER_R8B,  ZYDIS_REGISTER_R9B,  ZYDIS_REGISTER_R10B,
                    ZYDIS_REGISTER_R11B, ZYDIS_REGISTER_R12B, ZYDIS_REGISTER_R13B, ZYDIS_REGISTER_R14B, ZYDIS_REGISTER_R15B,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_AL,  ZYDIS_REGISTER_DL,  ZYDIS_REGISTER_BL,   ZYDIS_REGISTER_AH,  ZYDIS_REGISTER_CH,
                    ZYDIS_REGISTER_DH,  ZYDIS_REGISTER_BH,  ZYDIS_REGISTER_SPL,  ZYDIS_REGISTER_BPL, ZYDIS_REGISTER_SIL,
                    ZYDIS_REGISTER_DIL, ZYDIS_REGISTER_R8B, ZYDIS_REGISTER_R15B,
                };
            };

            struct Gp16Regs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_AX,   ZYDIS_REGISTER_CX,   ZYDIS_REGISTER_DX,   ZYDIS_REGISTER_BX,
                    ZYDIS_REGISTER_SP,   ZYDIS_REGISTER_BP,   ZYDIS_REGISTER_SI,   ZYDIS_REGISTER_DI,
                    ZYDIS_REGISTER_R8W,  ZYDIS_REGISTER_R9W,  ZYDIS_REGISTER_R10W, ZYDIS_REGISTER_R11W,
                    ZYDIS_REGISTER_R12W, ZYDIS_REGISTER_R13W, ZYDIS_REGISTER_R14W, ZYDIS_REGISTER_R15W,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_AX,  ZYDIS_REGISTER_CX,  ZYDIS_REGISTER_DX,   ZYDIS_REGISTER_BX,
                    ZYDIS_REGISTER_SP,  ZYDIS_REGISTER_BP,  ZYDIS_REGISTER_SI,   ZYDIS_REGISTER_DI,
                    ZYDIS_REGISTER_R8W, ZYDIS_REGISTER_R9W, ZYDIS_REGISTER_R15W,
                };
            };

            struct Gp32Regs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_EAX,  ZYDIS_REGISTER_ECX,  ZYDIS_REGISTER_EDX,  ZYDIS_REGISTER_EBX,
                    ZYDIS_REGISTER_ESP,  ZYDIS_REGISTER_EBP,  ZYDIS_REGISTER_ESI,  ZYDIS_REGISTER_EDI,
                    ZYDIS_REGISTER_R8D,  ZYDIS_REGISTER_R9D,  ZYDIS_REGISTER_R10D, ZYDIS_REGISTER_R11D,
                    ZYDIS_REGISTER_R12D, ZYDIS_REGISTER_R13D, ZYDIS_REGISTER_R14D, ZYDIS_REGISTER_R15D,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_EAX,  ZYDIS_REGISTER_ECX,  ZYDIS_REGISTER_EDX,  ZYDIS_REGISTER_EBX,
                    ZYDIS_REGISTER_R12D, ZYDIS_REGISTER_R13D, ZYDIS_REGISTER_R14D, ZYDIS_REGISTER_R15D,
                };
            };

            struct Gp64Regs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RBX,
                    ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI,
                    ZYDIS_REGISTER_R8,  ZYDIS_REGISTER_R9,  ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11,
                    ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RBX,
                    ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15,
                };
            };

            struct Gp8MemRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_AL,  ZYDIS_REGISTER_CL,   ZYDIS_REGISTER_DL,
                    ZYDIS_REGISTER_BL,   ZYDIS_REGISTER_DIL, ZYDIS_REGISTER_R15B,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_AL, ZYDIS_REGISTER_DL, ZYDIS_REGISTER_BL, ZYDIS_REGISTER_R15B,
                };
            };

            struct Gp16MemRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_IP, ZYDIS_REGISTER_AX,
                    ZYDIS_REGISTER_CX,   ZYDIS_REGISTER_DX, ZYDIS_REGISTER_R15W,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_NONE,
                    ZYDIS_REGISTER_IP,
                    ZYDIS_REGISTER_AX,
                    ZYDIS_REGISTER_R15W,
                };
            };

            struct Gp32MemRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_EIP, ZYDIS_REGISTER_EAX,
                    ZYDIS_REGISTER_ECX,  ZYDIS_REGISTER_EDX, ZYDIS_REGISTER_R15D,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_NONE,
                    ZYDIS_REGISTER_EIP,
                    ZYDIS_REGISTER_EAX,
                    ZYDIS_REGISTER_R15D,
                };
            };

            struct Gp64MemRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_RIP, ZYDIS_REGISTER_RAX,
                    ZYDIS_REGISTER_RCX,  ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_R15,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_NONE,
                    ZYDIS_REGISTER_RIP,
                    ZYDIS_REGISTER_RAX,
                    ZYDIS_REGISTER_R15,
                };
            };

            struct StRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_ST0, ZYDIS_REGISTER_ST1, ZYDIS_REGISTER_ST2, ZYDIS_REGISTER_ST3,
                    ZYDIS_REGISTER_ST4, ZYDIS_REGISTER_ST5, ZYDIS_REGISTER_ST6, ZYDIS_REGISTER_ST7,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_ST0,
                    ZYDIS_REGISTER_ST3,
                    ZYDIS_REGISTER_ST7,
                };
            };

            struct MmRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_MM0, ZYDIS_REGISTER_MM1, ZYDIS_REGISTER_MM2, ZYDIS_REGISTER_MM3,
                    ZYDIS_REGISTER_MM4, ZYDIS_REGISTER_MM5, ZYDIS_REGISTER_MM6, ZYDIS_REGISTER_MM7,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_MM0,
                    ZYDIS_REGISTER_MM3,
                    ZYDIS_REGISTER_MM7,
                };
            };

            struct XmmRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_XMM0,  ZYDIS_REGISTER_XMM1,  ZYDIS_REGISTER_XMM2,  ZYDIS_REGISTER_XMM3,
                    ZYDIS_REGISTER_XMM4,  ZYDIS_REGISTER_XMM5,  ZYDIS_REGISTER_XMM6,  ZYDIS_REGISTER_XMM7,
                    ZYDIS_REGISTER_XMM8,  ZYDIS_REGISTER_XMM9,  ZYDIS_REGISTER_XMM10, ZYDIS_REGISTER_XMM11,
                    ZYDIS_REGISTER_XMM12, ZYDIS_REGISTER_XMM13, ZYDIS_REGISTER_XMM14, ZYDIS_REGISTER_XMM15,
                    ZYDIS_REGISTER_XMM16, ZYDIS_REGISTER_XMM17, ZYDIS_REGISTER_XMM18, ZYDIS_REGISTER_XMM19,
                    ZYDIS_REGISTER_XMM20, ZYDIS_REGISTER_XMM21, ZYDIS_REGISTER_XMM22, ZYDIS_REGISTER_XMM23,
                    ZYDIS_REGISTER_XMM24, ZYDIS_REGISTER_XMM25, ZYDIS_REGISTER_XMM26, ZYDIS_REGISTER_XMM27,
                    ZYDIS_REGISTER_XMM28, ZYDIS_REGISTER_XMM29, ZYDIS_REGISTER_XMM30, ZYDIS_REGISTER_XMM31,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_XMM0,  ZYDIS_REGISTER_XMM4,  ZYDIS_REGISTER_XMM8,  ZYDIS_REGISTER_XMM12,
                    ZYDIS_REGISTER_XMM16, ZYDIS_REGISTER_XMM20, ZYDIS_REGISTER_XMM24, ZYDIS_REGISTER_XMM31,
                };
            };

            struct YmmRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_YMM0,  ZYDIS_REGISTER_YMM1,  ZYDIS_REGISTER_YMM2,  ZYDIS_REGISTER_YMM3,
                    ZYDIS_REGISTER_YMM4,  ZYDIS_REGISTER_YMM5,  ZYDIS_REGISTER_YMM6,  ZYDIS_REGISTER_YMM7,
                    ZYDIS_REGISTER_YMM8,  ZYDIS_REGISTER_YMM9,  ZYDIS_REGISTER_YMM10, ZYDIS_REGISTER_YMM11,
                    ZYDIS_REGISTER_YMM12, ZYDIS_REGISTER_YMM13, ZYDIS_REGISTER_YMM14, ZYDIS_REGISTER_YMM15,
                    ZYDIS_REGISTER_YMM16, ZYDIS_REGISTER_YMM17, ZYDIS_REGISTER_YMM18, ZYDIS_REGISTER_YMM19,
                    ZYDIS_REGISTER_YMM20, ZYDIS_REGISTER_YMM21, ZYDIS_REGISTER_YMM22, ZYDIS_REGISTER_YMM23,
                    ZYDIS_REGISTER_YMM24, ZYDIS_REGISTER_YMM25, ZYDIS_REGISTER_YMM26, ZYDIS_REGISTER_YMM27,
                    ZYDIS_REGISTER_YMM28, ZYDIS_REGISTER_YMM29, ZYDIS_REGISTER_YMM30, ZYDIS_REGISTER_YMM31,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_YMM0,  ZYDIS_REGISTER_YMM1,  ZYDIS_REGISTER_YMM2,  ZYDIS_REGISTER_YMM3,
                    ZYDIS_REGISTER_YMM4,  ZYDIS_REGISTER_YMM8,  ZYDIS_REGISTER_YMM12, ZYDIS_REGISTER_YMM16,
                    ZYDIS_REGISTER_YMM20, ZYDIS_REGISTER_YMM24, ZYDIS_REGISTER_YMM31,
                };
            };

            struct ZmmRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_ZMM0,  ZYDIS_REGISTER_ZMM1,  ZYDIS_REGISTER_ZMM2,  ZYDIS_REGISTER_ZMM3,
                    ZYDIS_REGISTER_ZMM4,  ZYDIS_REGISTER_ZMM5,  ZYDIS_REGISTER_ZMM6,  ZYDIS_REGISTER_ZMM7,
                    ZYDIS_REGISTER_ZMM8,  ZYDIS_REGISTER_ZMM9,  ZYDIS_REGISTER_ZMM10, ZYDIS_REGISTER_ZMM11,
                    ZYDIS_REGISTER_ZMM12, ZYDIS_REGISTER_ZMM13, ZYDIS_REGISTER_ZMM14, ZYDIS_REGISTER_ZMM15,
                    ZYDIS_REGISTER_ZMM16, ZYDIS_REGISTER_ZMM17, ZYDIS_REGISTER_ZMM18, ZYDIS_REGISTER_ZMM19,
                    ZYDIS_REGISTER_ZMM20, ZYDIS_REGISTER_ZMM21, ZYDIS_REGISTER_ZMM22, ZYDIS_REGISTER_ZMM23,
                    ZYDIS_REGISTER_ZMM24, ZYDIS_REGISTER_ZMM25, ZYDIS_REGISTER_ZMM26, ZYDIS_REGISTER_ZMM27,
                    ZYDIS_REGISTER_ZMM28, ZYDIS_REGISTER_ZMM29, ZYDIS_REGISTER_ZMM30, ZYDIS_REGISTER_ZMM31,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_ZMM0,  ZYDIS_REGISTER_ZMM1,  ZYDIS_REGISTER_ZMM2,  ZYDIS_REGISTER_ZMM3,
                    ZYDIS_REGISTER_ZMM4,  ZYDIS_REGISTER_ZMM8,  ZYDIS_REGISTER_ZMM12, ZYDIS_REGISTER_ZMM16,
                    ZYDIS_REGISTER_ZMM20, ZYDIS_REGISTER_ZMM24, ZYDIS_REGISTER_ZMM31,
                };
            };

            struct TmmRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_TMM0, ZYDIS_REGISTER_TMM1, ZYDIS_REGISTER_TMM2, ZYDIS_REGISTER_TMM3,
                    ZYDIS_REGISTER_TMM4, ZYDIS_REGISTER_TMM5, ZYDIS_REGISTER_TMM6, ZYDIS_REGISTER_TMM7,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_TMM0,
                    ZYDIS_REGISTER_TMM4,
                    ZYDIS_REGISTER_TMM7,
                };
            };

            struct MaskRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_K0, ZYDIS_REGISTER_K1, ZYDIS_REGISTER_K2, ZYDIS_REGISTER_K3,
                    ZYDIS_REGISTER_K4, ZYDIS_REGISTER_K5, ZYDIS_REGISTER_K6, ZYDIS_REGISTER_K7,
                };
                static constexpr ZydisRegister kTableSimple[] = {
                    ZYDIS_REGISTER_K0,
                    ZYDIS_REGISTER_K1,
                    ZYDIS_REGISTER_K5,
                    ZYDIS_REGISTER_K7,
                };
            };

        } // namespace Detail

        class OperandBase
        {
        public:
            virtual ZydisEncoderOperand current() = 0;

            virtual bool advance() = 0;
        };

        template<typename TClassTable, bool TSimple> class RegT : public OperandBase
        {
            BaseGenerator<ZydisRegister> _gen{ TSimple ? std::span<const ZydisRegister>(TClassTable::kTableSimple)
                                                       : std::span<const ZydisRegister>(TClassTable::kTable) };

        public:
            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_REGISTER;
                op.reg.value = _gen.current();
                return op;
            }

            bool advance() override
            {
                return _gen.advance();
            }
        };

        using Gp8 = RegT<Detail::Gp8Regs, false>;
        using Gp16 = RegT<Detail::Gp16Regs, false>;
        using Gp32 = RegT<Detail::Gp32Regs, false>;
        using Gp64 = RegT<Detail::Gp64Regs, false>;
        using St = RegT<Detail::StRegs, false>;
        using Mmx = RegT<Detail::MmRegs, false>;
        using Xmm = RegT<Detail::XmmRegs, false>;
        using Ymm = RegT<Detail::YmmRegs, false>;
        using Zmm = RegT<Detail::ZmmRegs, false>;
        using Tmm = RegT<Detail::TmmRegs, false>;
        using Mask = RegT<Detail::MaskRegs, false>;

        using Gp8Simple = RegT<Detail::Gp8Regs, true>;
        using Gp16Simple = RegT<Detail::Gp16Regs, true>;
        using Gp32Simple = RegT<Detail::Gp32Regs, true>;
        using Gp64Simple = RegT<Detail::Gp64Regs, true>;
        using StSimple = RegT<Detail::StRegs, true>;
        using MmxSimple = RegT<Detail::MmRegs, true>;
        using XmmSimple = RegT<Detail::XmmRegs, true>;
        using YmmSimple = RegT<Detail::YmmRegs, true>;
        using ZmmSimple = RegT<Detail::ZmmRegs, true>;
        using TmmSimple = RegT<Detail::TmmRegs, true>;
        using MaskSimple = RegT<Detail::MaskRegs, true>;

        struct RegImplicit : public OperandBase
        {
            ZydisRegister reg;

            RegImplicit(ZydisRegister reg)
                : reg(reg)
            {
            }

            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_REGISTER;
                op.reg.value = reg;
                return op;
            }

            bool advance() override
            {
                return false;
            }
        };

        class Imm : public OperandBase
        {
            static constexpr int64_t kValues[] = {
                0, 1, 3, 4, 6, 8, -1, -2, -3, -4, -8, -9, 0x7F, 0x7FFF, 0x7FFFFFFF, 0x7FFFFFFFFFFFFFFF, 0xF, 0xFF,
            };

            BaseGenerator<int64_t> _gen{ std::span(kValues) };

        public:
            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                op.imm.s = _gen.current();
                return op;
            }

            bool advance() override
            {
                return _gen.advance();
            }
        };

        class ImmSimple : public OperandBase
        {
            static constexpr int64_t kValues[] = {
                0,
                1,
                3,
            };

            BaseGenerator<int64_t> _gen{ std::span(kValues) };

        public:
            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                op.imm.s = _gen.current();
                return op;
            }

            bool advance() override
            {
                return _gen.advance();
            }
        };

        template<bool TSimple> class Rel8 : public OperandBase
        {
            static constexpr int64_t kValues[] = {
                2, 8, 16, -2, -8, -16,
            };
            static constexpr int64_t kValuesSimple[] = {
                16,
                -16,
            };

            BaseGenerator<int64_t> _gen{ TSimple ? std::span<const int64_t>(kValuesSimple)
                                                 : std::span<const int64_t>(kValues) };

        public:
            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                op.imm.s = _gen.current();
                return op;
            }

            bool advance() override
            {
                return _gen.advance();
            }
        };

        template<bool TSimple> class Rel32 : public OperandBase
        {
            static constexpr int64_t kValues[] = {
                1024, 0x7FFFFFFF, 0x7FFFFFFF, -1024, -0x7FFFFFFF, -0x7FFFFFFF,
            };
            static constexpr int64_t kValuesSimple[] = {
                1024,
                -1024,
            };

            BaseGenerator<int64_t> _gen{ TSimple ? std::span<const int64_t>(kValuesSimple)
                                                 : std::span<const int64_t>(kValues) };

        public:
            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                op.imm.s = _gen.current();
                return op;
            }

            bool advance() override
            {
                return _gen.advance();
            }
        };

        template<typename TRegClass, uint16_t TMemSize, bool TSimple> class MemT : public OperandBase
        {
            static constexpr uint8_t kScaleValues[] = { 1, 4, 8 };
            static constexpr uint8_t kScaleValuesSimple[] = { 1 };

            static constexpr int64_t kImmValues[] = {
                0,
                0x89FFFFF,
                -0x89FFFFF,
            };
            static constexpr int64_t kImmValuesSimple[] = {
                0,
            };

            BaseGenerator<ZydisRegister> _seg{ TSimple ? std::span<const ZydisRegister>(Detail::SegRegs::kTable)
                                                       : std::span<const ZydisRegister>(Detail::SegRegs::kTable) };

            BaseGenerator<ZydisRegister> _base{ TSimple ? std::span<const ZydisRegister>(TRegClass::kTableSimple)
                                                        : std::span<const ZydisRegister>(TRegClass::kTable) };

            BaseGenerator<ZydisRegister> _index{ TSimple ? std::span<const ZydisRegister>(TRegClass::kTableSimple)
                                                         : std::span<const ZydisRegister>(TRegClass::kTable) };

            BaseGenerator<int64_t> _disp{ TSimple ? std::span<const int64_t>(kImmValuesSimple)
                                                  : std::span<const int64_t>(kImmValues) };

            BaseGenerator<uint8_t> _scale{ TSimple ? std::span<const uint8_t>(kScaleValues)
                                                   : std::span<const uint8_t>(kScaleValues) };

        public:
            ZydisEncoderOperand current() override
            {
                ZydisEncoderOperand op{};
                op.type = ZYDIS_OPERAND_TYPE_MEMORY;
                op.mem.base = _base.current();
                op.mem.index = _index.current();
                op.mem.displacement = _disp.current();
                op.mem.scale = _scale.current();
                op.mem.size = TMemSize;
                return op;
            }

            bool advance() override
            {
                if (_base.advance())
                    return true;
                if (_index.advance())
                    return true;
                if (_disp.advance())
                    return true;
                if (_scale.advance())
                    return true;

                return false;
            }
        };

        using Mem8 = MemT<Detail::Gp8MemRegs, 1, false>;
        using Mem16 = MemT<Detail::Gp16MemRegs, 2, false>;
        using Mem32 = MemT<Detail::Gp32MemRegs, 4, false>;
        using Mem64 = MemT<Detail::Gp64MemRegs, 8, false>;

        using Mem8Simple = MemT<Detail::Gp8MemRegs, 1, true>;
        using Mem16Simple = MemT<Detail::Gp16MemRegs, 2, true>;
        using Mem32Simple = MemT<Detail::Gp32MemRegs, 4, true>;
        using Mem64Simple = MemT<Detail::Gp64MemRegs, 8, true>;

        class Operand
        {
            size_t _index{};
            std::vector<std::unique_ptr<OperandBase>> _gens;

        public:
            template<typename T, typename... Args> void add(Args&&... args)
            {
                _gens.push_back(std::make_unique<T>(std::forward<Args>(args)...));
            }

            ZydisEncoderOperand current()
            {
                assert(_index < _gens.size());

                return _gens[_index]->current();
            }

            bool advance()
            {
                if (_gens[_index]->advance())
                    return true;

                _index++;
                if (_index < _gens.size())
                    return true;

                _index = 0;
                return false;
            }

            bool empty() const
            {
                return _gens.empty();
            }
        };

        class Instr
        {
            ZydisMnemonic _mnemonic;
            std::vector<Operand> _opGens;

        public:
            Instr(ZydisMnemonic mnemonic)
                : _mnemonic(mnemonic)
            {
            }

            ZydisMnemonic mnemonic() const
            {
                return _mnemonic;
            }

            void addOpGen(Operand&& gen)
            {
                _opGens.push_back(std::move(gen));
            }

            ZydisEncoderRequest current()
            {
                ZydisEncoderRequest req{};
                req.mnemonic = _mnemonic;
                req.operand_count = _opGens.size();
                for (size_t i = 0; i < _opGens.size(); ++i)
                {
                    req.operands[i] = _opGens[i].current();
                }
                return req;
            }

            bool advance()
            {
                for (size_t i = 0; i < _opGens.size(); ++i)
                {
                    if (_opGens[i].advance())
                        return true;
                }
                return false;
            }
        };

    } // namespace Generators

    template<typename Full, typename Simple> static void addSel(Generators::Operand& gens, bool simplified)
    {
        if (simplified)
            gens.add<Simple>();
        else
            gens.add<Full>();
    }

    static Generators::Operand buildOpGenerators(ZydisMnemonic mnemonic, const ZydisOperandDefinition& opDef, bool simplified)
    {
        Generators::Operand gens;

        auto handleImplicitReg = [&]() {
            if (opDef.op.reg.type == ZYDIS_IMPLREG_TYPE_STATIC)
            {
                gens.add<Generators::RegImplicit>(static_cast<ZydisRegister>(opDef.op.reg.reg.reg));
            }
        };

        switch (opDef.type)
        {
            case ZYDIS_SEMANTIC_OPTYPE_IMPLICIT_REG:
                handleImplicitReg();
                break;

            case ZYDIS_SEMANTIC_OPTYPE_GPR8:
                addSel<Generators::Gp8, Generators::Gp8Simple>(gens, simplified);
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR16:
                addSel<Generators::Gp16, Generators::Gp16Simple>(gens, simplified);
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR32:
                addSel<Generators::Gp32, Generators::Gp32Simple>(gens, simplified);
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR64:
                addSel<Generators::Gp64, Generators::Gp64Simple>(gens, simplified);
                break;

            case ZYDIS_SEMANTIC_OPTYPE_GPR_ASZ:
            case ZYDIS_SEMANTIC_OPTYPE_GPR16_32_64:
                addSel<Generators::Gp16, Generators::Gp16Simple>(gens, simplified);
                addSel<Generators::Gp32, Generators::Gp32Simple>(gens, simplified);
                addSel<Generators::Gp64, Generators::Gp64Simple>(gens, simplified);
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR32_32_64:
                addSel<Generators::Gp32, Generators::Gp32Simple>(gens, simplified);
                addSel<Generators::Gp64, Generators::Gp64Simple>(gens, simplified);
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR16_32_32:
                addSel<Generators::Gp16, Generators::Gp16Simple>(gens, simplified);
                addSel<Generators::Gp32, Generators::Gp32Simple>(gens, simplified);
                break;

            case ZYDIS_SEMANTIC_OPTYPE_IMM:
                addSel<Generators::Imm, Generators::ImmSimple>(gens, simplified);
                break;
            case ZYDIS_SEMANTIC_OPTYPE_FPR:
                addSel<Generators::St, Generators::StSimple>(gens, simplified);
                break;
            case ZYDIS_SEMANTIC_OPTYPE_MMX:
                addSel<Generators::Mmx, Generators::MmxSimple>(gens, simplified);
                break;
            case ZYDIS_SEMANTIC_OPTYPE_XMM:
                addSel<Generators::Xmm, Generators::XmmSimple>(gens, simplified);
                break;
            case ZYDIS_SEMANTIC_OPTYPE_YMM:
                addSel<Generators::Ymm, Generators::YmmSimple>(gens, simplified);
                break;
            case ZYDIS_SEMANTIC_OPTYPE_MASK:
                addSel<Generators::Mask, Generators::MaskSimple>(gens, simplified);
                break;
            case ZYDIS_SEMANTIC_OPTYPE_ZMM:
                addSel<Generators::Zmm, Generators::ZmmSimple>(gens, simplified);
                break;

            case ZYDIS_SEMANTIC_OPTYPE_REL:
                addSel<Generators::Rel8<false>, Generators::Rel8<true>>(gens, simplified);
                addSel<Generators::Rel32<false>, Generators::Rel32<true>>(gens, simplified);
                break;

            case ZYDIS_SEMANTIC_OPTYPE_AGEN:
                addSel<Generators::Mem8, Generators::Mem8Simple>(gens, simplified);
                addSel<Generators::Mem16, Generators::Mem16Simple>(gens, simplified);
                addSel<Generators::Mem32, Generators::Mem32Simple>(gens, simplified);
                addSel<Generators::Mem64, Generators::Mem64Simple>(gens, simplified);
                break;

            default:
                break;
        }

        return gens;
    }

    static bool mnemonicPassesFilter(ZydisMnemonic mnemonic, const Filter& filter)
    {
        if (filter.mnemonics.none())
            return true;

        return filter.mnemonics.test(static_cast<size_t>(mnemonic));
    }

    static void createGeneratorsImpl(ZydisMnemonic mnemonic, bool simplified, std::vector<Generators::Instr>& instrs)
    {
        const ZydisEncodableInstruction* entries = nullptr;
        const auto countEntries = ZydisGetEncodableInstructions((ZydisMnemonic)mnemonic, &entries);

        for (ZyanU8 i = 0; i < countEntries; ++i)
        {
            const ZydisEncodableInstruction& entry = entries[i];

            const ZydisInstructionDefinition* base_definition = nullptr;
            ZydisGetInstructionDefinition(
                (ZydisInstructionEncoding)entry.encoding, entry.instruction_reference, &base_definition);

            const ZydisOperandDefinition* operandDefs = ZydisGetOperandDefinitions(base_definition);

            Generators::Instr instr((ZydisMnemonic)mnemonic);

            bool badCombination = false;
            for (uint8_t j = 0; j < base_definition->operand_count_visible; ++j)
            {
                const ZydisOperandDefinition& opDef = operandDefs[j];

                auto opGen = buildOpGenerators((ZydisMnemonic)mnemonic, opDef, simplified);
                if (opGen.empty())
                {
                    badCombination = true;
                    break;
                }

                instr.addOpGen(std::move(opGen));
            }

            if (badCombination)
                continue;

            instrs.push_back(std::move(instr));
        }
    }

    static std::vector<Generators::Instr> createGenerators(ZydisMnemonic mnemonic, bool simplified)
    {
        std::vector<Generators::Instr> instrs;

        createGeneratorsImpl(mnemonic, simplified, instrs);

        return instrs;
    }

    static std::vector<Generators::Instr> createGenerators(const Filter& filter, bool simplified)
    {
        std::vector<Generators::Instr> instrs;

        for (auto mnemonic = ZYDIS_MNEMONIC_INVALID + 1; mnemonic < ZYDIS_MNEMONIC_MAX_VALUE + 1; mnemonic++)
        {
            if (!filter.passes((ZydisMnemonic)mnemonic))
                continue;

            createGeneratorsImpl((ZydisMnemonic)mnemonic, simplified, instrs);
        }

        return instrs;
    }

    static std::string getHex(const uint8_t* data, size_t length)
    {
        std::string result;
        for (size_t i = 0; i < length; i++)
        {
            result += fmt::format("{:02X} ", data[i]);
        }
        return result;
    }

    static std::string getInstrText(const ZydisEncoderRequest& req)
    {
        auto opString = std::string{};
        for (size_t i = 0; i < req.operand_count; i++)
        {
            if (i > 0)
                opString += ", ";
            switch (req.operands[i].type)
            {
                case ZYDIS_OPERAND_TYPE_REGISTER:
                    opString += ZydisRegisterGetString(req.operands[i].reg.value);
                    break;
                case ZYDIS_OPERAND_TYPE_MEMORY:
                    opString += "MEM";
                    break;
                case ZYDIS_OPERAND_TYPE_POINTER:
                    opString += "PTR";
                    break;
                case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                    opString += fmt::format("{}", req.operands[i].imm.s);
                    break;
            }
        }

        return fmt::format("{} {}", ZydisMnemonicGetString(req.mnemonic), opString);
    }

    struct EncodeResult
    {
        ZyanStatus status{};
        uint8_t buf[15]{};
        uint8_t size{};
    };

    static EncodeResult checkEncode(ZydisEncoderRequest req, ZydisMachineMode mode)
    {
        req.machine_mode = mode;

        EncodeResult res{};

        ZyanUSize len = sizeof(res.buf);
        if (res.status = ZydisEncoderEncodeInstruction(&req, res.buf, &len); res.status != ZYAN_STATUS_SUCCESS)
        {
            return res;
        }

        res.size = static_cast<uint8_t>(len);
        return res;
    }

    template<bool TEnabled> struct CondLockGuard
    {
        std::mutex& mtx;
        bool enabled;

        CondLockGuard(std::mutex& mtx)
            : mtx{ mtx }
        {
            if constexpr (TEnabled)
            {
                mtx.lock();
            }
        }

        ~CondLockGuard()
        {
            if constexpr (TEnabled)
            {
                mtx.unlock();
            }
        }
    };

    static bool isSupportMnemonic(ZydisMnemonic mnemonic)
    {
        switch (mnemonic)
        {
            case ZYDIS_MNEMONIC_CLI:
            case ZYDIS_MNEMONIC_STI:
            case ZYDIS_MNEMONIC_UD0:
            case ZYDIS_MNEMONIC_UD1:
            case ZYDIS_MNEMONIC_UD2:
            case ZYDIS_MNEMONIC_RDRAND:
            case ZYDIS_MNEMONIC_RDSEED:
            case ZYDIS_MNEMONIC_RDTSC:
            case ZYDIS_MNEMONIC_RDTSCP:
                return false;

            // x87 instructions that push or pop the FPU stack change TOP, which breaks the
            // harness's static ST(i) -> physical-register mapping. They can't be captured
            // correctly here, so filter them. In-place x87 ops (FADD/FSUB/FABS/FCOM/...) are fine.
            case ZYDIS_MNEMONIC_FLD:
            case ZYDIS_MNEMONIC_FLD1:
            case ZYDIS_MNEMONIC_FLDZ:
            case ZYDIS_MNEMONIC_FLDL2T:
            case ZYDIS_MNEMONIC_FLDL2E:
            case ZYDIS_MNEMONIC_FLDPI:
            case ZYDIS_MNEMONIC_FLDLG2:
            case ZYDIS_MNEMONIC_FLDLN2:
            case ZYDIS_MNEMONIC_FILD:
            case ZYDIS_MNEMONIC_FBLD:
            case ZYDIS_MNEMONIC_FST:
            case ZYDIS_MNEMONIC_FSTP:
            case ZYDIS_MNEMONIC_FSTPNCE:
            case ZYDIS_MNEMONIC_FIST:
            case ZYDIS_MNEMONIC_FISTP:
            case ZYDIS_MNEMONIC_FISTTP:
            case ZYDIS_MNEMONIC_FBSTP:
            case ZYDIS_MNEMONIC_FADDP:
            case ZYDIS_MNEMONIC_FSUBP:
            case ZYDIS_MNEMONIC_FSUBRP:
            case ZYDIS_MNEMONIC_FMULP:
            case ZYDIS_MNEMONIC_FDIVP:
            case ZYDIS_MNEMONIC_FDIVRP:
            case ZYDIS_MNEMONIC_FCOMP:
            case ZYDIS_MNEMONIC_FCOMPP:
            case ZYDIS_MNEMONIC_FUCOMP:
            case ZYDIS_MNEMONIC_FUCOMPP:
            case ZYDIS_MNEMONIC_FICOMP:
            case ZYDIS_MNEMONIC_FCOMIP:
            case ZYDIS_MNEMONIC_FUCOMIP:
            case ZYDIS_MNEMONIC_FYL2X:
            case ZYDIS_MNEMONIC_FYL2XP1:
            case ZYDIS_MNEMONIC_FPATAN:
            case ZYDIS_MNEMONIC_FPTAN:
            case ZYDIS_MNEMONIC_FSINCOS:
            case ZYDIS_MNEMONIC_FXTRACT:
            case ZYDIS_MNEMONIC_FINCSTP:
            case ZYDIS_MNEMONIC_FDECSTP:
            case ZYDIS_MNEMONIC_FFREE:
            case ZYDIS_MNEMONIC_FFREEP:
                return false;
        }

        return true;
    }

    static bool isSupportedCategory(ZydisInstructionCategory category)
    {
        switch (category)
        {
            case ZYDIS_CATEGORY_COND_BR:
            case ZYDIS_CATEGORY_UNCOND_BR:
            case ZYDIS_CATEGORY_CALL:
            case ZYDIS_CATEGORY_RET:
            case ZYDIS_CATEGORY_INTERRUPT:
            case ZYDIS_CATEGORY_SYSCALL:
            case ZYDIS_CATEGORY_SYSTEM:
            case ZYDIS_CATEGORY_SYSRET:
            case ZYDIS_CATEGORY_IO:
            case ZYDIS_CATEGORY_IOSTRINGOP:
            case ZYDIS_CATEGORY_VTX:
            case ZYDIS_CATEGORY_TSX_LDTRK:
            case ZYDIS_CATEGORY_KEYLOCKER:
            case ZYDIS_CATEGORY_KEYLOCKER_WIDE:
            case ZYDIS_CATEGORY_PT:
            case ZYDIS_CATEGORY_WAITPKG:
            case ZYDIS_CATEGORY_CET:
            case ZYDIS_CATEGORY_RDRAND:
            case ZYDIS_CATEGORY_RDSEED:
            case ZYDIS_CATEGORY_RDPRU:
            case ZYDIS_CATEGORY_RDWRFSGS:
            case ZYDIS_CATEGORY_XSAVE:
            case ZYDIS_CATEGORY_SGX:
            case ZYDIS_CATEGORY_KNCSCALAR:
                return false;
        }
        return true;
    }

    static bool isSupportedIsaExt(ZydisISAExt isaExt)
    {
        const auto& info = Cpuid::getCpuInfo();

        switch (isaExt)
        {
            case ZYDIS_ISA_EXT_SSE4A:
                return info.sse4a;
            case ZYDIS_ISA_EXT_XOP:
                return info.xop;
            case ZYDIS_ISA_EXT_FMA4:
                return info.fma4;
            case ZYDIS_ISA_EXT_TBM:
                return info.tbm;
            case ZYDIS_ISA_EXT_GFNI:
                return info.gfni;
            case ZYDIS_ISA_EXT_VAES:
                return info.vaes;
            case ZYDIS_ISA_EXT_VPCLMULQDQ:
                return info.vpclmulqdq;
            case ZYDIS_ISA_EXT_AVX_VNNI:
                return info.avxvnni;
            case ZYDIS_ISA_EXT_SHA:
                return info.sha;
            case ZYDIS_ISA_EXT_SHA512:
                return info.sha512;
            case ZYDIS_ISA_EXT_SM3:
                return info.sm3;
            case ZYDIS_ISA_EXT_SM4:
                return info.sm4;
            case ZYDIS_ISA_EXT_AVX_IFMA:
                return info.avxifma;
            case ZYDIS_ISA_EXT_AVX_NE_CONVERT:
                return info.avxneconvert;
            case ZYDIS_ISA_EXT_AVX_VNNI_INT8:
                return info.avxvnniint8;
            case ZYDIS_ISA_EXT_AVX_VNNI_INT16:
                return info.avxvnniint16;
            case ZYDIS_ISA_EXT_CET:
                return info.cet;
            case ZYDIS_ISA_EXT_PKU:
                return info.pku;
            case ZYDIS_ISA_EXT_KEYLOCKER:
            case ZYDIS_ISA_EXT_KEYLOCKER_WIDE:
                return info.keylocker;
            case ZYDIS_ISA_EXT_MOVDIR:
                return info.movdir;
            case ZYDIS_ISA_EXT_ENQCMD:
                return info.enqcmd;
            case ZYDIS_ISA_EXT_RDPID:
                return info.rdpid;
            case ZYDIS_ISA_EXT_AVX:
                return info.avx;
            case ZYDIS_ISA_EXT_AVX2:
                return info.avx2;
            case ZYDIS_ISA_EXT_FMA:
                return info.fma;
            case ZYDIS_ISA_EXT_AES:
                return info.aes;
            case ZYDIS_ISA_EXT_AVXAES:
                return info.aes && info.avx;
            case ZYDIS_ISA_EXT_PCLMULQDQ:
                return info.pclmulqdq;
            case ZYDIS_ISA_EXT_F16C:
                return info.f16c;
            case ZYDIS_ISA_EXT_LZCNT:
                return info.lzcnt;
            case ZYDIS_ISA_EXT_ADOX_ADCX:
                return info.adx;
            case ZYDIS_ISA_EXT_RTM:
                return info.rtm;
            case ZYDIS_ISA_EXT_WAITPKG:
                return info.waitpkg;
            case ZYDIS_ISA_EXT_SERIALIZE:
                return info.serialize;
            case ZYDIS_ISA_EXT_AMX_TILE:
            case ZYDIS_ISA_EXT_AMX_INT8:
            case ZYDIS_ISA_EXT_AMX_BF16:
            case ZYDIS_ISA_EXT_AMX_FP16:
                return info.amx;
            default:
                return true;
        }
    }

    static bool isSupportedInstruction(const ZydisDisassembledInstruction& instr)
    {
        if (!isSupportedCategory(instr.info.meta.category))
            return false;

        if (!isSupportMnemonic(instr.info.mnemonic))
            return false;

        if (!isSupportedIsaExt(instr.info.meta.isa_ext))
            return false;

        if ((instr.info.attributes & ZYDIS_ATTRIB_IS_PRIVILEGED) != 0)
            return false;

        // APX uses the extended GPRs R16-R31, which the harness CONTEXT has no storage for.
        if (instr.info.meta.isa_ext == ZYDIS_ISA_EXT_APXEVEX || instr.info.meta.isa_ext == ZYDIS_ISA_EXT_APXLEGACY)
            return false;

        if (instr.info.meta.isa_ext == ZYDIS_ISA_EXT_UINTR)
            return false;

        if (instr.info.encoding == ZYDIS_INSTRUCTION_ENCODING_MVEX)
            return false;
        if (instr.info.encoding == ZYDIS_INSTRUCTION_ENCODING_EVEX)
            return false;

        for (std::size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            // A memory read/write operand the harness can't set up disqualifies the instruction, but an
            // AGEN operand only computes an address (its base/index registers are read, never the
            // memory itself), so it is fine.
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.type != ZYDIS_MEMOP_TYPE_AGEN)
                return false;
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                switch (ZydisRegisterGetClass(op.reg.value))
                {
                    case ZYDIS_REGCLASS_MMX:
                    case ZYDIS_REGCLASS_BOUND:
                    case ZYDIS_REGCLASS_TMM:
                        return false;
                    case ZYDIS_REGCLASS_YMM:
                        if (!Cpuid::getCpuInfo().avx2)
                            return false;
                        break;
                    case ZYDIS_REGCLASS_ZMM:
                    case ZYDIS_REGCLASS_MASK:
                        return false;
                }

                const auto enclosing = ZydisRegisterGetLargestEnclosing(instr.info.machine_mode, op.reg.value);
                if (enclosing >= ZYDIS_REGISTER_R16 && enclosing <= ZYDIS_REGISTER_R31)
                    return false;
            }
        }

        return true;
    }

    static bool isInstructionWritingRegs(const ZydisDisassembledInstruction& instr)
    {
        if (instr.info.cpu_flags->modified || instr.info.cpu_flags->undefined || instr.info.cpu_flags->set_0
            || instr.info.cpu_flags->set_1)
        {
            return true;
        }

        if (instr.info.fpu_flags->modified || instr.info.fpu_flags->undefined || instr.info.fpu_flags->set_0
            || instr.info.fpu_flags->set_1)
        {
            return true;
        }

        for (std::size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];

            if (op.type != ZYDIS_OPERAND_TYPE_REGISTER)
            {
                continue;
            }

            if ((op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) == 0)
            {
                continue;
            }

            switch (ZydisRegisterGetClass(op.reg.value))
            {
                case ZYDIS_REGCLASS_GPR8:
                case ZYDIS_REGCLASS_GPR16:
                case ZYDIS_REGCLASS_GPR32:
                case ZYDIS_REGCLASS_GPR64:
                case ZYDIS_REGCLASS_MMX:
                case ZYDIS_REGCLASS_XMM:
                case ZYDIS_REGCLASS_YMM:
                case ZYDIS_REGCLASS_ZMM:
                case ZYDIS_REGCLASS_MASK:
                case ZYDIS_REGCLASS_FLAGS:
                case ZYDIS_REGCLASS_X87:
                    return true;
                default:
                    break;
            }
        }

        return false;
    }

    template<bool TBuildInParallel>
    InstructionEntries buildInstructionsImpl(ZydisMachineMode mode, ZydisMnemonic mnemonic, ProgressReportFn reporter)
    {
        InstructionEntries res;

        std::mutex mtx;
        std::atomic<size_t> progress{};
        std::atomic<size_t> countInvalid{};

        auto instrGenerators = createGenerators(mnemonic, false);

        auto generateOne = [&](auto& instr) {
            for (;;)
            {
                auto req = instr.current();

                auto encodeRes = checkEncode(req, mode);
                bool isValid = encodeRes.status == ZYAN_STATUS_SUCCESS;

                ZydisDisassembledInstruction dis;
                if (isValid && ZYAN_SUCCESS(ZydisDisassembleIntel(mode, 0, encodeRes.buf, encodeRes.size, &dis))
                    && isSupportedInstruction(dis))
                {
                    CondLockGuard<TBuildInParallel> lock(mtx);

                    const auto entryOffset = static_cast<uint32_t>(res.instrData.size());

                    res.instrData.push_back(encodeRes.size);
                    res.instrData.insert(res.instrData.end(), encodeRes.buf, encodeRes.buf + encodeRes.size);

                    res.entryOffsets.push_back(entryOffset);
                }
                else
                {
                    countInvalid++;
                }

                if (!instr.advance())
                    break;
            }

            progress++;

            if (reporter)
                reporter(progress.load(), instrGenerators.size());
        };

        if constexpr (TBuildInParallel)
            parallelForEach(instrGenerators.begin(), instrGenerators.end(), generateOne);
        else
            std::for_each(instrGenerators.begin(), instrGenerators.end(), generateOne);

        return res;
    }

    static std::size_t getRegOffset(ZydisRegister reg);

    static std::string behaviorKey(const ZydisDisassembledInstruction& d)
    {
        std::string key;
        key += std::to_string(static_cast<int>(d.info.mnemonic));
        key += ':';
        key += std::to_string(static_cast<int>(d.info.encoding));
        key += ':';
        key += std::to_string(static_cast<int>(d.info.opcode_map));
        key += '.';
        key += std::to_string(static_cast<int>(d.info.opcode));

        sfl::static_vector<ZydisRegister, 12> slots;

        const auto slotOf = [&](ZydisRegister reg) -> int {
            const auto root = getEnclosingReg(d.info.machine_mode, reg);
            for (std::size_t s = 0; s < slots.size(); ++s)
                if (slots[s] == root)
                    return static_cast<int>(s);
            const int slot = static_cast<int>(slots.size());
            slots.push_back(root);
            return slot;
        };

        const auto appendReg = [&](ZydisRegister reg) {
            key += 'R';
            key += std::to_string(static_cast<int>(ZydisRegisterGetClass(reg)));
            key += '.';
            key += std::to_string(static_cast<int>(getRegOffset(reg)));
            key += '.';
            key += std::to_string(slotOf(reg));
            if (reg == ZYDIS_REGISTER_K0)
                key += 'z';
        };

        for (std::size_t i = 0; i < d.info.operand_count; ++i)
        {
            const auto& op = d.operands[i];
            key += ';';
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                appendReg(op.reg.value);
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                key += 'I';
                key += std::to_string(op.imm.value.u);
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                key += 'M';
                key += std::to_string(static_cast<int>(op.mem.type));
                key += '.';
                key += std::to_string(op.size);
                key += '.';
                if (op.mem.base != ZYDIS_REGISTER_NONE)
                    appendReg(op.mem.base);
                else
                    key += 'n';
                key += '.';
                if (op.mem.index != ZYDIS_REGISTER_NONE)
                    appendReg(op.mem.index);
                else
                    key += 'n';
                key += '.';
                key += std::to_string(static_cast<int>(op.mem.scale));
                key += '.';
                key += std::to_string(static_cast<long long>(op.mem.disp.value));
            }
        }
        return key;
    }

    InstructionEntries buildInstructions(
        ZydisMachineMode mode, ZydisMnemonic mnemonic, bool buildInParallel, ProgressReportFn reporter)
    {
        auto entries = [&]() {
            if (buildInParallel)
            {
                return buildInstructionsImpl<true>(mode, mnemonic, reporter);
            }
            else
            {
                return buildInstructionsImpl<false>(mode, mnemonic, reporter);
            }
        }();

        // Sort by length and bytes.
        std::sort(entries.entryOffsets.begin(), entries.entryOffsets.end(), [&](auto entryA, auto entryB) {
            const auto aLen = entries.instrData[entryA];
            const auto bLen = entries.instrData[entryB];

            if (aLen != bLen)
                return aLen < bLen;

            const auto aData = entries.instrData.data() + entryA + 1;
            const auto bData = entries.instrData.data() + entryB + 1;

            return std::lexicographical_compare(aData, aData + aLen, bData, bData + bLen);
        });

        // Remove entries where the data is identical.
        entries.entryOffsets.erase(
            std::unique(
                entries.entryOffsets.begin(), entries.entryOffsets.end(),
                [&](auto entryA, auto entryB) {
                    const auto aLen = entries.instrData[entryA];
                    const auto bLen = entries.instrData[entryB];

                    if (aLen != bLen)
                        return false;

                    const auto aData = entries.instrData.data() + entryA + 1;
                    const auto bData = entries.instrData.data() + entryB + 1;

                    return std::equal(aData, aData + aLen, bData);
                }),
            entries.entryOffsets.end());

        return entries;
    }

    static ZydisStackWidth getStackWidth(ZydisMachineMode mode)
    {
        switch (mode)
        {
            case ZYDIS_MACHINE_MODE_LONG_64:
                return ZYDIS_STACK_WIDTH_64;
            case ZYDIS_MACHINE_MODE_LEGACY_32:
                return ZYDIS_STACK_WIDTH_32;
            case ZYDIS_MACHINE_MODE_LEGACY_16:
                return ZYDIS_STACK_WIDTH_16;
            default:
                break;
        }
        return ZYDIS_STACK_WIDTH_64;
    }

    sfl::static_vector<ZydisRegister, 7> getWrittenRegisters(const ZydisDisassembledInstruction& dis)
    {
        std::bitset<ZYDIS_REGISTER_MAX_VALUE + 1> roots;
        sfl::static_vector<ZydisRegister, 7> result;

        for (const auto reg : getRegsModified(dis))
        {
            const auto rootReg = getRootReg(dis.info.machine_mode, reg);
            if (!roots.test(rootReg))
            {
                roots.set(rootReg);
                result.push_back(rootReg);
            }
        }

        return result;
    }

    sfl::static_vector<ZydisRegister, 7> getReadRegisters(const ZydisDisassembledInstruction& dis)
    {
        std::bitset<ZYDIS_REGISTER_MAX_VALUE + 1> roots;
        sfl::static_vector<ZydisRegister, 7> result;

        for (const auto reg : getRegsRead(dis))
        {
            if (!isRegFiltered(reg))
            {
                const auto rootReg = getRootReg(dis.info.machine_mode, reg);
                if (!roots.test(rootReg))
                {
                    roots.set(rootReg);
                    result.push_back(rootReg);
                }
            }
        }

        return result;
    }

    std::vector<ZydisMnemonic> buildMnemonicIndex(ZydisMachineMode mode, const Filter& filter)
    {
        Logging::startProgress("Building instruction combination index...");

        std::bitset<ZYDIS_MNEMONIC_MAX_VALUE + 1> selected;

        ZydisDecoder decoder{};
        ZydisDecoderInit(&decoder, mode, getStackWidth(mode));

        auto generators = createGenerators(filter, true);

        std::atomic<size_t> i = 0;
        size_t totalGenerators = generators.size();

        parallelForEach(generators.begin(), generators.end(), [&](auto& instr) {
            Logging::updateProgress(i.fetch_add(1) + 1, totalGenerators);

            const auto mnemonic = instr.mnemonic();
            if (selected[mnemonic])
                return;

            for (;;)
            {
                const auto encodeRes = checkEncode(instr.current(), mode);
                if (encodeRes.status == ZYAN_STATUS_SUCCESS)
                {
                    ZydisDisassembledInstruction dis{};
                    if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, encodeRes.buf, encodeRes.size, &dis.info, dis.operands))
                        && isSupportedInstruction(dis) && filter.passes(dis.info.meta.category)
                        && filter.passes(dis.info.meta.isa_ext))
                    {
                        if (!isInstructionWritingRegs(dis))
                        {
#ifndef NDEBUG
                            const char* mnemonicStr = ZydisMnemonicGetString(dis.info.mnemonic);
                            Logging::println("Instruction {} not writing regs", mnemonicStr);
#endif
                            return;
                        }

                        selected.set(mnemonic);
                        return;
                    }
                }

                if (!instr.advance())
                    return;
            }
        });

        Logging::endProgress();

        std::vector<ZydisMnemonic> result;
        for (int m = ZYDIS_MNEMONIC_INVALID + 1; m <= ZYDIS_MNEMONIC_MAX_VALUE; ++m)
        {
            if (!selected[m])
                continue;
            // The intentionally-undefined opcodes have encodings that disassemble inconsistently and
            // destabilize generation; never build them.
            if (m == ZYDIS_MNEMONIC_UD0 || m == ZYDIS_MNEMONIC_UD1 || m == ZYDIS_MNEMONIC_UD2)
                continue;
            result.push_back(static_cast<ZydisMnemonic>(m));
        }

        return result;
    }

    static std::atomic<bool> g_stopOnImpossible{ false };
    static std::atomic<bool> g_stopRequested{ false };
    static std::mutex g_reportMutex;
    static std::string g_impossibleReport;

    void setStopOnImpossible(bool enable)
    {
        g_stopOnImpossible.store(enable);
    }

    bool stopRequested()
    {
        return g_stopRequested.load();
    }

    std::string takeImpossibleReport()
    {
        std::lock_guard<std::mutex> lock(g_reportMutex);
        return g_impossibleReport;
    }

    static constexpr auto kAbortTestCaseThreshold = 100'000;
    static constexpr auto kReportInputsThreshold = kAbortTestCaseThreshold * 80 / 100;

    static sfl::static_vector<ZydisRegister, 7> getRegsUsed(const ZydisDisassembledInstruction& instr)
    {
        sfl::small_flat_set<ZydisRegister, 7> regs;
        for (std::size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                if (!isRegFiltered(op.reg.value))
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
        return sortRegs(regs);
    }

    static std::uint32_t getFlagsRead(const ZydisDisassembledInstruction& instr)
    {
        std::uint32_t flags = 0;
        flags |= instr.info.cpu_flags->tested;
        // In order to capture what undefined result it needs to force feeding them as inputs prior.
        // It captures keep vs overwrite behavior, which is what the harness needs to know to set up the inputs correctly.
        flags |= instr.info.cpu_flags->undefined;

        switch (instr.info.mnemonic)
        {
            case ZYDIS_MNEMONIC_SHL:
            case ZYDIS_MNEMONIC_SHR:
            case ZYDIS_MNEMONIC_SAR:
            case ZYDIS_MNEMONIC_ROL:
            case ZYDIS_MNEMONIC_ROR:
            case ZYDIS_MNEMONIC_RCL:
            case ZYDIS_MNEMONIC_RCR:
            case ZYDIS_MNEMONIC_SHLD:
            case ZYDIS_MNEMONIC_SHRD:
                flags |= instr.info.cpu_flags->modified;
                break;
            default:
                break;
        }

        return flags;
    }

    static std::size_t getRegOffset(ZydisRegister reg)
    {
        switch (reg)
        {
            case ZYDIS_REGISTER_AH:
            case ZYDIS_REGISTER_BH:
            case ZYDIS_REGISTER_CH:
            case ZYDIS_REGISTER_DH:
                return 1;
        }
        return 0;
    }

    static void advanceInputs(
        Execution::ScopedContext& ctx, std::mt19937_64& prng, std::vector<InputGenerator>& inputGens,
        const ZydisDisassembledInstruction& instr, TestCaseEntry& testEntry, std::size_t iteration)
    {
        const auto regsRead = getRegsRead(instr);
        const auto flagsRead = getFlagsRead(instr);
        const auto flagsSet0 = getFlagsSet0(instr);
        const auto flagsSet1 = getFlagsSet1(instr);

        sfl::small_flat_set<ZydisRegister, 5> regsReadBig;
        for (const auto& reg : regsRead)
        {
            const auto bigReg = getRootReg(instr.info.machine_mode, reg);
            regsReadBig.insert(bigReg);
        }

        // Cleanse the registers.
        for (const auto& reg : regsReadBig)
        {
            if (isRegFiltered(reg))
                continue;

            const auto bigRegSize = static_cast<size_t>(ZydisRegisterGetWidth(instr.info.machine_mode, reg) / 8);
            constexpr uint8_t ccBytes[] = {
                0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            };
            ctx.setRegBytes(reg, std::span<const std::uint8_t>{ ccBytes, bigRegSize });
        }

#ifdef _DEBUG
        sfl::static_vector<std::pair<ZydisRegister, std::vector<std::uint8_t>>, 5> regData;
#endif

        // Randomize read registers.
        size_t regIndex = 0;
        for (const auto& reg : regsRead)
        {
            if (isRegFiltered(reg))
                continue;

            std::uint8_t regBuf[256]{};
            const std::size_t usedRegBitSize = ZydisRegisterGetWidth(instr.info.machine_mode, reg);
            const std::size_t usedRegByteSize = usedRegBitSize / 8;
            const auto bigReg = getRootReg(instr.info.machine_mode, reg);
            const std::size_t bigRegBitSize = ZydisRegisterGetWidth(instr.info.machine_mode, bigReg);
            const std::size_t bigRegByteSize = bigRegBitSize / 8;

            // In case inputs are ah, al we need to re-use the existing data in the root register.
            auto currentBytes = ctx.getRegBytes(bigReg);
            std::memcpy(regBuf, currentBytes.data(), currentBytes.size());
            const auto regOffset = getRegOffset(reg);

            auto& inputGen = inputGens[regIndex];

            const auto inputData = inputGen.current();
            // Iterations 0 and 1 are guaranteed all-operands-zero and all-operands-ones passes:
            // the random per-operand sweep almost never lands every input on the same extreme at
            // once, which is what result-is-zero (e.g. ZF after OR) or result-is-all-ones (e.g.
            // PEXT with an all-ones mask) outputs require.
            if (iteration == 0)
                std::memset(regBuf + regOffset, 0x00, usedRegByteSize);
            else if (iteration == 1)
                std::memset(regBuf + regOffset, 0xFF, usedRegByteSize);
            else
                std::memcpy(regBuf + regOffset, inputData.data(), usedRegByteSize);

            ctx.setRegBytes(bigReg, std::span<const std::uint8_t>{ regBuf, bigRegByteSize });

            testEntry.inputRegs[bigReg] = RegTestData{ regBuf, regBuf + bigRegByteSize };

            regIndex++;

#ifdef _DEBUG
            if (iteration >= kReportInputsThreshold)
            {
                regData.emplace_back(
                    reg, std::vector<std::uint8_t>{ regBuf + regOffset, regBuf + regOffset + usedRegByteSize });
            }
#endif
        }

        for (size_t inputIdx = 0; inputIdx < regIndex; ++inputIdx)
        {
            if (inputGens[inputIdx].advance())
            {
                if ((iteration + 1) % 3 == 0)
                    break;
            }
        }

        // Randomize read flags.
        std::optional<std::uint32_t> inputFlags;
        if (flagsRead != 0)
        {
            std::uint32_t setFlags = 0;
            for (std::size_t i = 0; i < 32; ++i)
            {
                if ((flagsRead & (1 << i)) != 0)
                {
                    setFlags |= (prng() % 2) << i;
                }
            }
            inputFlags = setFlags;
        }

        if (flagsSet0 != 0)
        {
            std::uint32_t setFlags = 0;
            for (std::size_t i = 0; i < 32; ++i)
            {
                if ((flagsSet0 & (1 << i)) != 0)
                {
                    setFlags |= 1U << i;
                }
            }
            inputFlags = inputFlags.value_or(0) | setFlags;
        }

        if (flagsSet1 != 0)
        {
            inputFlags = inputFlags.value_or(0);
        }

        // Ensure we never have TF set.
        if (inputFlags)
        {
            inputFlags = inputFlags.value_or(0) & ~ZYDIS_CPUFLAG_TF;
        }

        if (inputFlags)
        {
            testEntry.inputFlags = *inputFlags;
        }

        ctx.setRegValue(ZYDIS_REGISTER_EFLAGS, inputFlags.value_or(0));

#if defined(_DEBU) && 0
        if (iteration >= kReportInputsThreshold)
        {
            std::string inputsStr;
            for (const auto& [reg, data] : regData)
            {
                inputsStr += fmt::format("{}=#{} ", ZydisRegisterGetString(reg), Utils::hexEncode(data));
            }

            Logging::println("Test: {} - Inputs: {}", instr.text, inputsStr);
        }
#endif
    }

    static int regDataBit(const RegTestData& data, ZydisRegister reg, std::uint16_t bitPos)
    {
        const auto regOffset = getRegOffset(reg);
        // The raw memory of all registers are stored little endian so the first bit is in the last byte.
        const auto byteOffset = regOffset + ((bitPos / 8) ^ (sizeof(data[0]) - 1));
        if (byteOffset >= data.size())
            return -1;
        return (data[byteOffset] >> (bitPos % 8)) & 0x01;
    }

    static void presetModifiedRegs(
        ZydisMachineMode mode, Execution::ScopedContext& ctx, const ZydisDisassembledInstruction& instr, std::uint8_t value)
    {
        std::uint8_t regBuf[256];
        std::memset(regBuf, value, sizeof(regBuf));

        for (const auto reg : getRegsModified(instr))
        {
            const auto bigReg = getRootReg(mode, reg);
            const std::size_t bigRegSize = ZydisRegisterGetWidth(mode, bigReg) / 8;
            ctx.setRegBytes(bigReg, std::span<const std::uint8_t>{ regBuf, bigRegSize });
        }
    }

    static void reapplyInputs(Execution::ScopedContext& ctx, const TestCaseEntry& input)
    {
        for (const auto& [bigReg, bytes] : input.inputRegs)
        {
            ctx.setRegBytes(bigReg, std::span<const std::uint8_t>{ bytes.data(), bytes.size() });
        }
        ctx.setRegValue(ZYDIS_REGISTER_EFLAGS, input.inputFlags.value_or(0));
    }

    static void captureOutputs(
        Execution::ScopedContext& ctx, const ZydisDisassembledInstruction& instr, TestCaseEntry& testEntry)
    {
        for (const auto regModified : getRegsModified(instr))
        {
            const auto bigReg = getRootReg(instr.info.machine_mode, regModified);
            const auto bigSize = ZydisRegisterGetWidth(instr.info.machine_mode, bigReg);

            const auto regData = ctx.getRegBytes(bigReg);

            testEntry.outputRegs[bigReg] = RegTestData{ regData.begin(), regData.begin() + (bigSize / 8) };
        }

        if (getFlagsModified(instr) != 0 || getFlagsSet0(instr) != 0 || getFlagsSet1(instr) != 0)
        {
            testEntry.outputFlags = ctx.getRegValue<uint32_t>(ZYDIS_REGISTER_EFLAGS);

            // Remove all flags that are not reported by Zydis.
            const auto* cpuFlags = instr.info.cpu_flags;
            *testEntry.outputFlags &= (cpuFlags->modified | cpuFlags->set_0 | cpuFlags->set_1 | cpuFlags->undefined);
        }
    }

    static std::string getTestInfo(const TestBitInfo& info)
    {
        std::string res;
        res = fmt::format("{}[{}] = 0b{}", ZydisRegisterGetString(info.reg), info.bitPos, info.expectedBitValue);
        return res;
    }

    static void hostCpuid(std::uint32_t leaf, std::uint32_t subleaf, std::uint32_t out[4])
    {
#ifdef _WIN32
        int regs[4];
        __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
        out[0] = static_cast<std::uint32_t>(regs[0]);
        out[1] = static_cast<std::uint32_t>(regs[1]);
        out[2] = static_cast<std::uint32_t>(regs[2]);
        out[3] = static_cast<std::uint32_t>(regs[3]);
#else
        unsigned int a = 0, b = 0, c = 0, d = 0;
        __cpuid_count(leaf, subleaf, a, b, c, d);
        out[0] = a;
        out[1] = b;
        out[2] = c;
        out[3] = d;
#endif
    }

    static void buildCpuidPairs(CpuidSweep& sweep)
    {
        std::unordered_set<std::uint64_t> seen;
        const auto add = [&](std::uint32_t leaf, std::uint32_t subleaf) {
            const std::uint64_t key = (static_cast<std::uint64_t>(leaf) << 32) | subleaf;
            if (seen.insert(key).second)
                sweep.pairs.emplace_back(leaf, subleaf);
        };

        std::uint32_t r[4];
        hostCpuid(0, 0, r);
        const std::uint32_t maxStd = r[0];
        hostCpuid(0x80000000u, 0, r);
        const std::uint32_t maxExt = r[0];

        std::uint32_t maxHyp = 0;
        hostCpuid(0x40000000u, 0, r);
        if (r[0] > 0x40000000u && r[0] <= 0x400000FFu)
            maxHyp = r[0];

        const auto enumRange = [&](std::uint32_t first, std::uint32_t last) {
            for (std::uint64_t l = first; l <= last; ++l)
            {
                const auto leaf = static_cast<std::uint32_t>(l);
                std::uint32_t out0[4];
                hostCpuid(leaf, 0, out0);
                add(leaf, 0);

                std::uint32_t out1[4];
                hostCpuid(leaf, 1, out1);
                const bool varies = out1[0] != out0[0] || out1[1] != out0[1] || out1[2] != out0[2] || out1[3] != out0[3];
                if (!varies)
                    continue;

                add(leaf, 1);
                const bool sparse = leaf == 0x0Du;
                int zeroRun = 0;
                for (std::uint32_t sub = 2; sub < 64; ++sub)
                {
                    std::uint32_t o[4];
                    hostCpuid(leaf, sub, o);
                    if (o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] == 0)
                    {
                        if (!sparse && ++zeroRun >= 2)
                            break;
                    }
                    else
                    {
                        zeroRun = 0;
                        add(leaf, sub);
                    }
                }
            }
        };

        enumRange(0, maxStd);
        enumRange(0x80000000u, maxExt);
        if (maxHyp != 0)
            enumRange(0x40000000u, maxHyp);

        add(maxStd + 1, 0);
        add(0x40000000u, 0);
        add(maxExt + 1, 0);
        add(0xFFFFFFFFu, 0);

        std::mt19937_64 rng(0x9E3779B97F4A7C15ull);
        const std::uint32_t clusters[] = {
            0, maxStd, 0x40000000u, 0x80000000u, maxExt, 0xC0000000u, 0xFFFFFFFFu,
        };
        std::size_t attempts = 0;
        while (sweep.pairs.size() < 50000 && attempts < 5'000'000)
        {
            ++attempts;
            std::uint32_t leaf;
            if ((rng() & 1) == 0)
            {
                const auto center = clusters[rng() % (sizeof(clusters) / sizeof(clusters[0]))];
                leaf = center + static_cast<std::uint32_t>(rng() % 256) - 128;
            }
            else
            {
                leaf = static_cast<std::uint32_t>(rng());
            }
            const std::uint32_t subleaf = (rng() & 3) == 0 ? static_cast<std::uint32_t>(rng() % 64)
                                                           : static_cast<std::uint32_t>(rng());
            add(leaf, subleaf);
        }
    }

    static std::vector<InputGenerator> setupInputGenerators(
        std::mt19937_64& prng, const ZydisDisassembledInstruction& instr, CpuidSweep* cpuidSweep)
    {
        std::vector<InputGenerator> generators;

        const auto regsRead = getRegsRead(instr);

        // Generate input generators for registers.
        for (const auto& reg : regsRead)
        {
            if (isRegFiltered(reg))
                continue;

            if (cpuidSweep != nullptr)
            {
                const auto root = getRootReg(instr.info.machine_mode, reg);
                if (root == ZYDIS_REGISTER_RAX)
                {
                    generators.emplace_back(cpuidSweep, 0, true, prng);
                    continue;
                }
                if (root == ZYDIS_REGISTER_RCX)
                {
                    generators.emplace_back(cpuidSweep, 1, false, prng);
                    continue;
                }
            }

            const auto regSize = ZydisRegisterGetWidth(instr.info.machine_mode, reg);
            generators.emplace_back(regSize, prng);
        }

        return generators;
    }

    static bool isInputFromImmediate(const ZydisDisassembledInstruction& instr)
    {
        for (std::size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                return true;
        }
        return false;
    }

    static void testInstruction(ZydisMachineMode mode, InstrTestGroup& testCase)
    {
        auto& instrData = testCase.instrData;

        ZydisDisassembledInstruction instr{};
        ZydisDisassembleIntel(mode, 0, instrData.data(), instrData.size(), &instr);

        if (!isSupportedInstruction(instr))
            return;

        const bool isCpuid = instr.info.mnemonic == ZYDIS_MNEMONIC_CPUID;

        const auto isInputImmediate = isInputFromImmediate(instr);
        const auto maxAttempts = isInputImmediate ? kAbortTestCaseThreshold / 3 : kAbortTestCaseThreshold;

        const auto testMatrix = isCpuid ? std::vector<TestBitInfo>{} : generateTestMatrix(instr);
        if (!isCpuid && testMatrix.empty())
            return;

        auto ctx = Execution::ScopedContext(mode, instrData);
        if (!ctx)
        {
            Logging::println("Failed to prepare context");
            return;
        }

        testCase.address = ctx.getCodeAddress();

        const auto seed = static_cast<std::size_t>(instr.info.mnemonic);
        std::mt19937_64 prng(seed);

        CpuidSweep cpuidSweep;
        if (isCpuid)
            buildCpuidPairs(cpuidSweep);

        auto inputGenerators = setupInputGenerators(prng, instr, isCpuid ? &cpuidSweep : nullptr);

        if (isCpuid)
        {
            ctx.pinThread(0);
            while (!cpuidSweep.exhausted())
            {
                TestCaseEntry input{};
                advanceInputs(ctx, prng, inputGenerators, instr, input, 2);
                if (!ctx.execute())
                    return;
                if (ctx.getExecutionStatus() != Execution::ExecutionStatus::Success)
                    continue;

                TestCaseEntry outA{};
                captureOutputs(ctx, instr, outA);
                input.outputRegs = std::move(outA.outputRegs);
                input.outputFlags = outA.outputFlags;
                testCase.entries.push_back(std::move(input));
            }
            return;
        }

        sfl::static_flat_set<ZydisRegister, 10> readRoots;
        for (const auto reg : getRegsRead(instr))
            readRoots.insert(getRootReg(instr.info.machine_mode, reg));

        bool needTwoRuns = false;
        for (const auto reg : getRegsModified(instr))
        {
            if (readRoots.count(getRootReg(instr.info.machine_mode, reg)) == 0)
            {
                needTwoRuns = true;
                break;
            }
        }

        const auto toExceptionType = [](Execution::ExecutionStatus status) {
            switch (status)
            {
                case Execution::ExecutionStatus::ExceptionIntDivideError:
                    return ExceptionType::DivideError;
                case Execution::ExecutionStatus::ExceptionIntOverflow:
                    return ExceptionType::IntegerOverflow;
            }
            return ExceptionType::None;
        };

        std::vector<bool> satisfied(testMatrix.size(), false);
        std::size_t satisfiedCount = 0;

        std::size_t iteration = 0;
        bool illegalInstr = false;

        while (satisfiedCount < testMatrix.size() && iteration <= maxAttempts && !illegalInstr)
        {
            TestCaseEntry input{};
            advanceInputs(ctx, prng, inputGenerators, instr, input, iteration);
            iteration++;

            testCase.totalAttempts++;

            TestCaseEntry outA{};
            TestCaseEntry outB{};

            presetModifiedRegs(mode, ctx, instr, needTwoRuns ? 0xFF : 0x00);
            reapplyInputs(ctx, input);
            if (!ctx.execute())
            {
                Logging::println("Failed to execute instruction");
                return;
            }
            auto statusA = ctx.getExecutionStatus();
            if (statusA == Execution::ExecutionStatus::IllegalInstruction)
            {
                illegalInstr = true;
                break;
            }
            if (statusA == Execution::ExecutionStatus::Success)
                captureOutputs(ctx, instr, outA);

            auto statusB = statusA;
            if (needTwoRuns)
            {
                presetModifiedRegs(mode, ctx, instr, 0x00);
                reapplyInputs(ctx, input);
                if (!ctx.execute())
                {
                    Logging::println("Failed to execute instruction");
                    return;
                }
                statusB = ctx.getExecutionStatus();
                if (statusB == Execution::ExecutionStatus::IllegalInstruction)
                {
                    illegalInstr = true;
                    break;
                }
                if (statusB == Execution::ExecutionStatus::Success)
                    captureOutputs(ctx, instr, outB);
            }
            else
            {
                outB = outA;
            }

            const auto exceptionA = toExceptionType(statusA);

            for (std::size_t t = 0; t < testMatrix.size(); ++t)
            {
                if (satisfied[t])
                    continue;

                const TestBitInfo& tb = testMatrix[t];

                if (tb.exceptionType != ExceptionType::None)
                {
                    if (exceptionA == tb.exceptionType)
                    {
                        TestCaseEntry entry = input;
                        entry.exceptionType = tb.exceptionType;
                        testCase.entries.push_back(std::move(entry));
                        satisfied[t] = true;
                        satisfiedCount++;
                    }
                    continue;
                }

                if (statusA != Execution::ExecutionStatus::Success || statusB != Execution::ExecutionStatus::Success)
                    continue;

                if (tb.reg == ZYDIS_REGISTER_FLAGS)
                {
                    if (!outA.outputFlags)
                        continue;
                    const int bit = (*outA.outputFlags >> tb.bitPos) & 1;
                    if (bit == tb.expectedBitValue)
                    {
                        TestCaseEntry entry = input;
                        entry.outputRegs = outA.outputRegs;
                        entry.outputFlags = outA.outputFlags;
                        testCase.entries.push_back(std::move(entry));
                        satisfied[t] = true;
                        satisfiedCount++;
                    }
                    continue;
                }

                const auto bigReg = getRootReg(mode, tb.reg);
                const auto itA = outA.outputRegs.find(bigReg);
                const auto itB = outB.outputRegs.find(bigReg);
                if (itA == outA.outputRegs.end() || itB == outB.outputRegs.end())
                    continue;

                const int aBit = regDataBit(itA->second, tb.reg, tb.bitPos);
                const int bBit = regDataBit(itB->second, tb.reg, tb.bitPos);
                if (aBit >= 0 && aBit == bBit && aBit == tb.expectedBitValue)
                {
                    TestCaseEntry entry = input;
                    entry.outputRegs = outA.outputRegs;
                    entry.outputFlags = outA.outputFlags;
                    testCase.entries.push_back(std::move(entry));
                    satisfied[t] = true;
                    satisfiedCount++;
                }
            }
        }

        if (illegalInstr)
        {
            testCase.illegalInstruction = true;
            return;
        }

        for (std::size_t t = 0; t < testMatrix.size(); ++t)
        {
            if (!satisfied[t])
            {
                const auto report = fmt::format("Test probably impossible: {} ; {}", instr.text, getTestInfo(testMatrix[t]));
                Logging::println("{}", report);
                if (g_stopOnImpossible.load() && !g_stopRequested.exchange(true))
                {
                    std::lock_guard<std::mutex> lock(g_reportMutex);
                    g_impossibleReport = report;
                }
            }
        }
    }

    static void collectEntryFacts(const TestCaseEntry& entry, std::vector<std::uint64_t>& facts)
    {
        facts.clear();
        for (const auto& [reg, data] : entry.outputRegs)
        {
            const std::size_t bits = data.size() * 8;
            for (std::size_t b = 0; b < bits; ++b)
            {
                const std::uint64_t value = (data[b / 8] >> (b % 8)) & 1;
                facts.push_back((static_cast<std::uint64_t>(reg) << 32) | (static_cast<std::uint64_t>(b) << 1) | value);
            }
        }
        if (entry.outputFlags)
        {
            for (std::size_t i = 0; i < 32; ++i)
            {
                const std::uint64_t value = (*entry.outputFlags >> i) & 1;
                facts.push_back(
                    (static_cast<std::uint64_t>(ZYDIS_REGISTER_FLAGS) << 32) | (static_cast<std::uint64_t>(i) << 1) | value);
            }
        }
        if (entry.exceptionType)
        {
            facts.push_back(0xE000000000000000ull | static_cast<std::uint64_t>(*entry.exceptionType));
        }
    }

    static void minimizeEntries(std::vector<TestCaseEntry>& entries)
    {
        if (entries.size() <= 1)
            return;

        std::vector<std::vector<std::uint64_t>> facts(entries.size());
        std::unordered_set<std::uint64_t> universe;
        for (std::size_t i = 0; i < entries.size(); ++i)
        {
            collectEntryFacts(entries[i], facts[i]);
            universe.insert(facts[i].begin(), facts[i].end());
        }

        std::unordered_set<std::uint64_t> covered;
        std::vector<bool> picked(entries.size(), false);
        std::vector<TestCaseEntry> result;

        while (covered.size() < universe.size())
        {
            std::size_t bestIdx = entries.size();
            std::size_t bestGain = 0;
            for (std::size_t i = 0; i < entries.size(); ++i)
            {
                if (picked[i])
                    continue;

                std::size_t gain = 0;
                for (const auto fact : facts[i])
                {
                    if (covered.count(fact) == 0)
                        gain++;
                }

                if (gain > bestGain)
                {
                    bestGain = gain;
                    bestIdx = i;
                }
            }

            if (bestIdx == entries.size())
                break;

            picked[bestIdx] = true;
            covered.insert(facts[bestIdx].begin(), facts[bestIdx].end());
            result.push_back(std::move(entries[bestIdx]));
        }

        entries = std::move(result);
    }

    InstrTestGroup generateInstructionTestData(ZydisMachineMode mode, std::span<const std::uint8_t> instrData)
    {
        InstrTestGroup testCase{};
        testCase.instrData = instrData;

        if (g_stopRequested.load())
            return testCase;

        testInstruction(mode, testCase);

        ZydisDisassembledInstruction dis{};
        const bool isCpuid = ZYAN_SUCCESS(ZydisDisassembleIntel(mode, 0, instrData.data(), instrData.size(), &dis))
            && dis.info.mnemonic == ZYDIS_MNEMONIC_CPUID;

        // Remove duplicate entries.
        std::sort(testCase.entries.begin(), testCase.entries.end());

        auto last = std::unique(testCase.entries.begin(), testCase.entries.end());
        testCase.entries.erase(last, testCase.entries.end());

        if (!isCpuid)
            minimizeEntries(testCase.entries);
        std::sort(testCase.entries.begin(), testCase.entries.end());

        return testCase;
    }

    static InstrTestGroup relabelGroup(
        ZydisMachineMode mode, const InstrTestGroup& rep, std::span<const std::uint8_t> repBytes,
        std::span<const std::uint8_t> varBytes)
    {
        InstrTestGroup out = rep;
        out.instrData = varBytes;
        out.totalAttempts = 0;

        ZydisDisassembledInstruction dr{};
        ZydisDisassembledInstruction dv{};
        ZydisDisassembleIntel(mode, 0, repBytes.data(), repBytes.size(), &dr);
        ZydisDisassembleIntel(mode, 0, varBytes.data(), varBytes.size(), &dv);

        sfl::static_flat_map<ZydisRegister, ZydisRegister, 10> rootMap;
        for (std::size_t i = 0; i < dr.info.operand_count && i < dv.info.operand_count; ++i)
        {
            const auto& r = dr.operands[i];
            const auto& v = dv.operands[i];
            if (r.type == ZYDIS_OPERAND_TYPE_REGISTER && v.type == ZYDIS_OPERAND_TYPE_REGISTER)
                rootMap[getRootReg(mode, r.reg.value)] = getRootReg(mode, v.reg.value);
            else if (r.type == ZYDIS_OPERAND_TYPE_MEMORY && v.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (r.mem.base != ZYDIS_REGISTER_NONE && v.mem.base != ZYDIS_REGISTER_NONE)
                    rootMap[getRootReg(mode, r.mem.base)] = getRootReg(mode, v.mem.base);
                if (r.mem.index != ZYDIS_REGISTER_NONE && v.mem.index != ZYDIS_REGISTER_NONE)
                    rootMap[getRootReg(mode, r.mem.index)] = getRootReg(mode, v.mem.index);
            }
        }

        const auto remap = [&](sfl::small_flat_map<ZydisRegister, RegTestData, 2>& regs) {
            sfl::small_flat_map<ZydisRegister, RegTestData, 2> next;
            for (auto& [reg, data] : regs)
            {
                const auto it = rootMap.find(reg);
                next[it != rootMap.end() ? it->second : reg] = data;
            }
            regs = std::move(next);
        };

        for (auto& entry : out.entries)
        {
            remap(entry.inputRegs);
            remap(entry.outputRegs);
        }
        return out;
    }

    std::vector<InstrTestGroup> generateGroupedTestData(
        ZydisMachineMode mode, const InstructionEntries& instrs, ProgressReportFn reporter)
    {
        std::unordered_map<std::string, std::vector<std::uint32_t>> groups;
        for (const auto off : instrs.entryOffsets)
        {
            const auto length = instrs.instrData[off];
            const auto* data = instrs.instrData.data() + off + 1;
            ZydisDisassembledInstruction d{};
            std::string key;
            if (ZYAN_SUCCESS(ZydisDisassembleIntel(mode, 0, data, length, &d)))
                key = behaviorKey(d);
            else
                key = "?" + std::to_string(off);
            groups[std::move(key)].push_back(off);
        }

        std::vector<std::vector<std::uint32_t>> groupList;
        groupList.reserve(groups.size());
        for (auto& [k, v] : groups)
            groupList.push_back(std::move(v));

        std::vector<InstrTestGroup> result;
        std::mutex mtx;
        std::atomic<std::size_t> progress{ 0 };

        parallelForEach(groupList.begin(), groupList.end(), [&](const std::vector<std::uint32_t>& grp) {
            const auto repOff = grp[0];
            const std::span<const std::uint8_t> repSpan{ instrs.instrData.data() + repOff + 1, instrs.instrData[repOff] };
            InstrTestGroup rep = generateInstructionTestData(mode, repSpan);

            std::vector<InstrTestGroup> local;
            local.push_back(rep);
            if (!rep.illegalInstruction && !rep.entries.empty())
            {
                for (std::size_t i = 1; i < grp.size(); ++i)
                {
                    const auto vOff = grp[i];
                    const std::span<const std::uint8_t> vSpan{ instrs.instrData.data() + vOff + 1, instrs.instrData[vOff] };
                    local.push_back(relabelGroup(mode, rep, repSpan, vSpan));
                }
            }

            {
                std::lock_guard<std::mutex> lock(mtx);
                for (auto& g : local)
                    result.push_back(std::move(g));
            }

            if (reporter)
                reporter(progress.fetch_add(1) + 1, groupList.size());
        });

        return result;
    }

} // namespace x86Tester::Generator