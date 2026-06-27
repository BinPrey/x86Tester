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
#include <memory>
#include <mutex>
#include <random>
#include <sfl/small_flat_set.hpp>
#include <sfl/static_vector.hpp>
#include <span>
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
            };

            struct Gp8Regs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_AL,   ZYDIS_REGISTER_CL,   ZYDIS_REGISTER_DL,   ZYDIS_REGISTER_BL,   ZYDIS_REGISTER_AH,
                    ZYDIS_REGISTER_CH,   ZYDIS_REGISTER_DH,   ZYDIS_REGISTER_BH,   ZYDIS_REGISTER_SPL,  ZYDIS_REGISTER_BPL,
                    ZYDIS_REGISTER_SIL,  ZYDIS_REGISTER_DIL,  ZYDIS_REGISTER_R8B,  ZYDIS_REGISTER_R9B,  ZYDIS_REGISTER_R10B,
                    ZYDIS_REGISTER_R11B, ZYDIS_REGISTER_R12B, ZYDIS_REGISTER_R13B, ZYDIS_REGISTER_R14B, ZYDIS_REGISTER_R15B,
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
            };

            struct Gp32Regs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_EAX,  ZYDIS_REGISTER_ECX,  ZYDIS_REGISTER_EDX,  ZYDIS_REGISTER_EBX,
                    ZYDIS_REGISTER_ESP,  ZYDIS_REGISTER_EBP,  ZYDIS_REGISTER_ESI,  ZYDIS_REGISTER_EDI,
                    ZYDIS_REGISTER_R8D,  ZYDIS_REGISTER_R9D,  ZYDIS_REGISTER_R10D, ZYDIS_REGISTER_R11D,
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
            };

            struct Gp8MemRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_AL,  ZYDIS_REGISTER_CL,   ZYDIS_REGISTER_DL,
                    ZYDIS_REGISTER_BL,   ZYDIS_REGISTER_DIL, ZYDIS_REGISTER_R15B,
                };
            };

            struct Gp16MemRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_IP, ZYDIS_REGISTER_AX,
                    ZYDIS_REGISTER_CX,   ZYDIS_REGISTER_DX, ZYDIS_REGISTER_R15W,
                };
            };

            struct Gp32MemRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_EIP, ZYDIS_REGISTER_EAX,
                    ZYDIS_REGISTER_ECX,  ZYDIS_REGISTER_EDX, ZYDIS_REGISTER_R15D,
                };
            };

            struct Gp64MemRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_RIP, ZYDIS_REGISTER_RAX,
                    ZYDIS_REGISTER_RCX,  ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_R15,
                };
            };

            struct StRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_ST0, ZYDIS_REGISTER_ST1, ZYDIS_REGISTER_ST2, ZYDIS_REGISTER_ST3,
                    ZYDIS_REGISTER_ST4, ZYDIS_REGISTER_ST5, ZYDIS_REGISTER_ST6, ZYDIS_REGISTER_ST7,
                };
            };

            struct MmRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_MM0, ZYDIS_REGISTER_MM1, ZYDIS_REGISTER_MM2, ZYDIS_REGISTER_MM3,
                    ZYDIS_REGISTER_MM4, ZYDIS_REGISTER_MM5, ZYDIS_REGISTER_MM6, ZYDIS_REGISTER_MM7,
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
            };

            struct TmmRegs
            {
                static constexpr ZydisRegister kTable[] = {
                    ZYDIS_REGISTER_TMM0, ZYDIS_REGISTER_TMM1, ZYDIS_REGISTER_TMM2, ZYDIS_REGISTER_TMM3,
                    ZYDIS_REGISTER_TMM4, ZYDIS_REGISTER_TMM5, ZYDIS_REGISTER_TMM6, ZYDIS_REGISTER_TMM7,
                };
            };

        } // namespace Detail

        class OperandBase
        {
        public:
            virtual ZydisEncoderOperand current() = 0;

            virtual bool advance() = 0;
        };

        template<typename TClassTable> class RegT : public OperandBase
        {
            BaseGenerator<ZydisRegister> _gen{ TClassTable::kTable };

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

        using Gp8 = RegT<Detail::Gp8Regs>;
        using Gp16 = RegT<Detail::Gp16Regs>;
        using Gp32 = RegT<Detail::Gp32Regs>;
        using Gp64 = RegT<Detail::Gp64Regs>;
        using St = RegT<Detail::StRegs>;
        using Mmx = RegT<Detail::MmRegs>;
        using Xmm = RegT<Detail::XmmRegs>;
        using Ymm = RegT<Detail::YmmRegs>;
        using Zmm = RegT<Detail::ZmmRegs>;
        using Tmm = RegT<Detail::TmmRegs>;

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

        class Rel8 : public OperandBase
        {
            static constexpr int64_t kValues[] = {
                2, 8, 16, -2, -8, -16,
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

        class Rel32 : public OperandBase
        {
            static constexpr int64_t kValues[] = {
                1024, 0x7FFFFFFF, 0x7FFFFFFF, -1024, -0x7FFFFFFF, -0x7FFFFFFF,
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

        template<typename TRegClass, uint16_t TMemSize> class MemT : public OperandBase
        {
            static constexpr uint8_t kScaleValues[] = { 1, 4, 8 };
            static constexpr int64_t kImmValues[] = {
                0,
                0x89FFFFF,
                -0x89FFFFF,
            };

            BaseGenerator<ZydisRegister> _seg{ std::span(Detail::SegRegs::kTable) };
            BaseGenerator<ZydisRegister> _base{ std::span(TRegClass::kTable) };
            BaseGenerator<ZydisRegister> _index{ std::span(TRegClass::kTable) };
            BaseGenerator<int64_t> _disp{ std::span(kImmValues) };
            BaseGenerator<uint8_t> _scale{ std::span(kScaleValues) };

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

        using Mem8 = MemT<Detail::Gp8MemRegs, 1>;
        using Mem16 = MemT<Detail::Gp16MemRegs, 2>;
        using Mem32 = MemT<Detail::Gp32MemRegs, 4>;
        using Mem64 = MemT<Detail::Gp64MemRegs, 8>;

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

    static Generators::Operand buildOpGenerators(ZydisMnemonic mnemonic, const ZydisOperandDefinition& opDef)
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
                gens.add<Generators::Gp8>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR16:
                gens.add<Generators::Gp16>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR32:
                gens.add<Generators::Gp32>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR64:
                gens.add<Generators::Gp64>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR16_32_64:
                gens.add<Generators::Gp16>();
                gens.add<Generators::Gp32>();
                gens.add<Generators::Gp64>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR32_32_64:
                gens.add<Generators::Gp32>();
                gens.add<Generators::Gp64>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR16_32_32:
                gens.add<Generators::Gp16>();
                gens.add<Generators::Gp32>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_GPR_ASZ:
                gens.add<Generators::Gp16>();
                gens.add<Generators::Gp32>();
                gens.add<Generators::Gp64>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_IMM:
                gens.add<Generators::Imm>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_FPR:
                gens.add<Generators::St>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_MMX:
                gens.add<Generators::Mmx>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_XMM:
                gens.add<Generators::Xmm>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_YMM:
                gens.add<Generators::Ymm>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_ZMM:
                gens.add<Generators::Zmm>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_REL:
                gens.add<Generators::Rel8>();
                gens.add<Generators::Rel32>();
                break;
            case ZYDIS_SEMANTIC_OPTYPE_AGEN:
                gens.add<Generators::Mem8>();
                gens.add<Generators::Mem16>();
                gens.add<Generators::Mem32>();
                gens.add<Generators::Mem64>();
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

    static std::vector<Generators::Instr> createGenerators(const Filter& filter)
    {
        std::vector<Generators::Instr> instrs;

        for (auto mnemonic = ZYDIS_MNEMONIC_INVALID + 1; mnemonic < ZYDIS_MNEMONIC_MAX_VALUE + 1; mnemonic++)
        {
            if (!mnemonicPassesFilter((ZydisMnemonic)mnemonic, filter))
                continue;

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

                    auto opGen = buildOpGenerators((ZydisMnemonic)mnemonic, opDef);
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

    EncodeResult checkEncode(ZydisEncoderRequest req, ZydisMachineMode mode)
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

    template<bool TBuildInParallel>
    InstructionEntries buildInstructionsImpl(ZydisMachineMode mode, const Filter& filter, ProgressReportFn reporter)
    {
        InstructionEntries res;

        std::mutex mtx;
        std::atomic<size_t> progress{};
        std::atomic<size_t> countInvalid{};

        auto instrGenerators = createGenerators(filter);

        auto generateOne = [&](auto& instr) {
            for (;;)
            {
                auto req = instr.current();

                auto encodeRes = checkEncode(req, mode);
                bool isValid = encodeRes.status == ZYAN_STATUS_SUCCESS;

                if (isValid)
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

    InstructionEntries buildInstructions(
        ZydisMachineMode mode, const Filter& filter, bool buildInParallel, ProgressReportFn reporter)
    {
        auto entries = [&]() {
            if (buildInParallel)
            {
                return buildInstructionsImpl<true>(mode, filter, reporter);
            }
            else
            {
                return buildInstructionsImpl<false>(mode, filter, reporter);
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

    bool isSupportedCategory(ZydisInstructionCategory category)
    {
        switch (category)
        {
            case ZYDIS_CATEGORY_COND_BR:
            case ZYDIS_CATEGORY_UNCOND_BR:
            case ZYDIS_CATEGORY_CALL:
            case ZYDIS_CATEGORY_RET:
            case ZYDIS_CATEGORY_INTERRUPT:
            case ZYDIS_CATEGORY_SYSCALL:
            case ZYDIS_CATEGORY_SYSRET:
            case ZYDIS_CATEGORY_IO:
            case ZYDIS_CATEGORY_IOSTRINGOP:
            case ZYDIS_CATEGORY_KEYLOCKER:
            case ZYDIS_CATEGORY_KEYLOCKER_WIDE:
                return false;
        }
        return true;
    }

    bool isSupportedIsaExt(ZydisISAExt isaExt)
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

    std::vector<MnemonicInfo> buildMnemonicIndex(ZydisMachineMode mode)
    {
        std::vector<MnemonicInfo> res(ZYDIS_MNEMONIC_MAX_VALUE + 1);

        auto generators = createGenerators(Filter{});
        for (auto& instr : generators)
        {
            const auto mnemonic = instr.mnemonic();
            if (res[mnemonic].encodable)
                continue;

            for (int attempt = 0; attempt < 65536; ++attempt)
            {
                const auto encodeRes = checkEncode(instr.current(), mode);
                if (encodeRes.status == ZYAN_STATUS_SUCCESS)
                {
                    ZydisDisassembledInstruction dis{};
                    if (ZYAN_SUCCESS(ZydisDisassembleIntel(mode, 0, encodeRes.buf, encodeRes.size, &dis)))
                    {
                        res[mnemonic].encodable = true;
                        res[mnemonic].category = dis.info.meta.category;
                        res[mnemonic].isaExt = dis.info.meta.isa_ext;
                    }
                    break;
                }

                if (!instr.advance())
                    break;
            }
        }

        return res;
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

    static sfl::static_vector<ZydisRegister, 5> getRegsUsed(const ZydisDisassembledInstruction& instr)
    {
        sfl::small_flat_set<ZydisRegister, 5> regs;
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

    static std::vector<InputGenerator> setupInputGenerators(std::mt19937_64& prng, const ZydisDisassembledInstruction& instr)
    {
        std::vector<InputGenerator> generators;

        const auto regsRead = getRegsRead(instr);

        // Generate input generators for registers.
        for (const auto& reg : regsRead)
        {
            if (isRegFiltered(reg))
                continue;

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

    static bool isSupportedInstruction(const ZydisDisassembledInstruction& instr)
    {
        if ((instr.info.attributes & ZYDIS_ATTRIB_IS_PRIVILEGED) != 0)
            return false;

        if (!isSupportedCategory(instr.info.meta.category))
            return false;

        // APX uses the extended GPRs R16-R31, which the harness CONTEXT has no storage for.
        if (instr.info.meta.isa_ext == ZYDIS_ISA_EXT_APXEVEX || instr.info.meta.isa_ext == ZYDIS_ISA_EXT_APXLEGACY)
            return false;

        if (!isSupportedIsaExt(instr.info.meta.isa_ext))
            return false;

        if (instr.info.encoding == ZYDIS_INSTRUCTION_ENCODING_MVEX)
            return false;
        if (instr.info.encoding == ZYDIS_INSTRUCTION_ENCODING_EVEX && !Cpuid::getCpuInfo().avx512f)
            return false;

        for (std::size_t i = 0; i < instr.info.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            // A hidden memory operand the harness can't set up disqualifies the instruction, but an
            // AGEN operand only computes an address (its base/index registers are read, never the
            // memory itself), so it is fine.
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.type != ZYDIS_MEMOP_TYPE_AGEN
                && op.visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN)
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
                        if (!Cpuid::getCpuInfo().avx512f)
                            return false;
                        break;
                }

                const auto enclosing = ZydisRegisterGetLargestEnclosing(instr.info.machine_mode, op.reg.value);
                if (enclosing >= ZYDIS_REGISTER_R16 && enclosing <= ZYDIS_REGISTER_R31)
                    return false;
            }
        }

        switch (instr.info.mnemonic)
        {
            case ZYDIS_MNEMONIC_CLI:
            case ZYDIS_MNEMONIC_STI:
            case ZYDIS_MNEMONIC_CPUID:
            case ZYDIS_MNEMONIC_RDTSC:
            case ZYDIS_MNEMONIC_RDTSCP:
            case ZYDIS_MNEMONIC_RDPMC:
            case ZYDIS_MNEMONIC_RDRAND:
            case ZYDIS_MNEMONIC_RDSEED:
            case ZYDIS_MNEMONIC_RDPID:
            case ZYDIS_MNEMONIC_RDPRU:
            case ZYDIS_MNEMONIC_RDFSBASE:
            case ZYDIS_MNEMONIC_RDGSBASE:
            case ZYDIS_MNEMONIC_WRFSBASE:
            case ZYDIS_MNEMONIC_WRGSBASE:
            case ZYDIS_MNEMONIC_SLDT:
            case ZYDIS_MNEMONIC_STR:
            case ZYDIS_MNEMONIC_SGDT:
            case ZYDIS_MNEMONIC_SIDT:
            case ZYDIS_MNEMONIC_SMSW:
            case ZYDIS_MNEMONIC_UD0:
            case ZYDIS_MNEMONIC_UD1:
            case ZYDIS_MNEMONIC_UD2:
            case ZYDIS_MNEMONIC_XGETBV:
            case ZYDIS_MNEMONIC_XTEST:
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

    static void testInstruction(ZydisMachineMode mode, InstrTestGroup& testCase)
    {
        auto& instrData = testCase.instrData;

        ZydisDisassembledInstruction instr{};
        ZydisDisassembleIntel(mode, 0, instrData.data(), instrData.size(), &instr);

        if (!isSupportedInstruction(instr))
            return;

        const auto isInputImmediate = isInputFromImmediate(instr);
        const auto maxAttempts = isInputImmediate ? kAbortTestCaseThreshold / 3 : kAbortTestCaseThreshold;

        const auto testMatrix = generateTestMatrix(instr);
        if (testMatrix.empty())
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

        sfl::small_flat_set<ZydisRegister, 5> readRoots;
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

        auto inputGenerators = setupInputGenerators(prng, instr);

        std::vector<bool> satisfied(testMatrix.size(), false);
        std::size_t satisfiedCount = 0;

        std::size_t iteration = 0;
        bool illegalInstr = false;

        while (satisfiedCount < testMatrix.size() && iteration <= maxAttempts && !illegalInstr)
        {
            TestCaseEntry input{};
            advanceInputs(ctx, prng, inputGenerators, instr, input, iteration);
            iteration++;

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

        // Remove duplicate entries.
        std::sort(testCase.entries.begin(), testCase.entries.end());

        auto last = std::unique(testCase.entries.begin(), testCase.entries.end());
        testCase.entries.erase(last, testCase.entries.end());

        minimizeEntries(testCase.entries);
        std::sort(testCase.entries.begin(), testCase.entries.end());

        return testCase;
    }

} // namespace x86Tester::Generator