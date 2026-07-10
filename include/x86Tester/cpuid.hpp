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
        bool avx512f : 1;
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
        bool rdpid : 1;
        bool rtm : 1;
        bool waitpkg : 1;
        bool gfni : 1;
        bool vaes : 1;
        bool vpclmulqdq : 1;
        bool avxvnni : 1;
        bool sha512 : 1;
        bool sm3 : 1;
        bool sm4 : 1;
        bool avxifma : 1;
        bool avxneconvert : 1;
        bool avxvnniint8 : 1;
        bool avxvnniint16 : 1;
        bool cet : 1;
        bool pku : 1;
        bool keylocker : 1;
        bool movdir : 1;
        bool enqcmd : 1;
        bool serialize : 1;
        bool amx : 1;
    };

    const CpuInfo& getCpuInfo();

} // namespace x86Tester::Cpuid
