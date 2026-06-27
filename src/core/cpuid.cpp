#include "x86Tester/cpuid.hpp"

#include <cstring>

#ifdef _WIN32
#    include <intrin.h>
#else
#    include <cpuid.h>
#endif

namespace x86Tester::Cpuid
{
    namespace
    {
        void cpuid(std::uint32_t leaf, std::uint32_t subleaf, std::uint32_t regs[4])
        {
#ifdef _WIN32
            int out[4] = {};
            __cpuidex(out, static_cast<int>(leaf), static_cast<int>(subleaf));
            regs[0] = static_cast<std::uint32_t>(out[0]);
            regs[1] = static_cast<std::uint32_t>(out[1]);
            regs[2] = static_cast<std::uint32_t>(out[2]);
            regs[3] = static_cast<std::uint32_t>(out[3]);
#else
            if (!__get_cpuid_count(leaf, subleaf, &regs[0], &regs[1], &regs[2], &regs[3]))
            {
                regs[0] = regs[1] = regs[2] = regs[3] = 0;
            }
#endif
        }

        std::string queryCpuName()
        {
            std::uint32_t ext[4] = {};
            cpuid(0x80000000u, 0, ext);
            if (ext[0] < 0x80000004u)
                return "unknown-cpu";

            std::uint32_t regs[12] = {};
            cpuid(0x80000002u, 0, &regs[0]);
            cpuid(0x80000003u, 0, &regs[4]);
            cpuid(0x80000004u, 0, &regs[8]);

            char raw[49] = {};
            std::memcpy(raw, regs, 48);

            std::string name;
            bool pendingSep = false;
            for (char c : raw)
            {
                if (c == '\0')
                    break;
                const bool alnum = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
                if (alnum)
                {
                    if (pendingSep && !name.empty())
                        name.push_back('_');
                    pendingSep = false;
                    name.push_back(c);
                }
                else
                {
                    pendingSep = true;
                }
            }

            return name.empty() ? "unknown-cpu" : name;
        }

        CpuInfo buildCpuInfo()
        {
            CpuInfo info{};
            info.name = queryCpuName();

            std::uint32_t r[4] = {};
            cpuid(1u, 0, r);
            const std::uint32_t eax = r[0];
            const std::uint32_t baseFamily = (eax >> 8) & 0xFu;
            const std::uint32_t baseModel = (eax >> 4) & 0xFu;
            info.stepping = eax & 0xFu;
            info.family = baseFamily + (baseFamily == 0xFu ? ((eax >> 20) & 0xFFu) : 0u);
            info.model = baseModel | ((baseFamily == 0x6u || baseFamily == 0xFu) ? (((eax >> 16) & 0xFu) << 4) : 0u);
            info.sse3 = (r[2] & (1u << 0)) != 0;
            info.pclmulqdq = (r[2] & (1u << 1)) != 0;
            info.ssse3 = (r[2] & (1u << 9)) != 0;
            info.fma = (r[2] & (1u << 12)) != 0;
            info.sse41 = (r[2] & (1u << 19)) != 0;
            info.sse42 = (r[2] & (1u << 20)) != 0;
            info.popcnt = (r[2] & (1u << 23)) != 0;
            info.aes = (r[2] & (1u << 25)) != 0;
            info.avx = (r[2] & (1u << 28)) != 0;
            info.f16c = (r[2] & (1u << 29)) != 0;
            info.rdrand = (r[2] & (1u << 30)) != 0;
            info.mmx = (r[3] & (1u << 23)) != 0;
            info.sse = (r[3] & (1u << 25)) != 0;
            info.sse2 = (r[3] & (1u << 26)) != 0;

            cpuid(7u, 0, r);
            info.bmi1 = (r[1] & (1u << 3)) != 0;
            info.avx2 = (r[1] & (1u << 5)) != 0;
            info.avx512f = (r[1] & (1u << 16)) != 0;
            info.bmi2 = (r[1] & (1u << 8)) != 0;
            info.rdseed = (r[1] & (1u << 18)) != 0;
            info.adx = (r[1] & (1u << 19)) != 0;
            info.sha = (r[1] & (1u << 29)) != 0;

            std::uint32_t ext[4] = {};
            cpuid(0x80000000u, 0, ext);
            if (ext[0] >= 0x80000001u)
            {
                cpuid(0x80000001u, 0, r);
                info.lahf = (r[2] & (1u << 0)) != 0;
                info.lzcnt = (r[2] & (1u << 5)) != 0;
                info.sse4a = (r[2] & (1u << 6)) != 0;
                info.xop = (r[2] & (1u << 11)) != 0;
                info.fma4 = (r[2] & (1u << 16)) != 0;
                info.tbm = (r[2] & (1u << 21)) != 0;
            }

            return info;
        }
    }

    const CpuInfo& getCpuInfo()
    {
        static const CpuInfo info = buildCpuInfo();
        return info;
    }

} // namespace x86Tester::Cpuid
