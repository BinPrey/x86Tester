#pragma once

#include <cstdint>
#include <string>

namespace x86Tester::Cpuid
{
    struct CpuInfo
    {
        std::string name;
        std::uint32_t family;
        std::uint32_t model;
        std::uint32_t stepping;
        bool mmx : 1;
        bool sse : 1;
        bool sse2 : 1;
        bool sse3 : 1;
        bool ssse3 : 1;
        bool sse41 : 1;
        bool sse42 : 1;
        bool sse4a : 1;
        bool avx : 1;
        bool avx2 : 1;
        bool fma : 1;
        bool fma4 : 1;
        bool xop : 1;
        bool tbm : 1;
        bool bmi1 : 1;
        bool bmi2 : 1;
        bool popcnt : 1;
        bool lzcnt : 1;
        bool lahf : 1;
        bool aes : 1;
        bool pclmulqdq : 1;
        bool f16c : 1;
        bool sha : 1;
        bool adx : 1;
        bool rdrand : 1;
        bool rdseed : 1;
    };

    const CpuInfo& getCpuInfo();

} // namespace x86Tester::Cpuid
