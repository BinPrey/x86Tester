#pragma once

#include <chrono>
#include <cstdio>
#ifdef _WIN32
#    include <intrin.h>
#else
#    include <immintrin.h>
#endif
#include <Zydis/Zydis.h>
#include <fmt/format.h>
#include <iostream>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace x86Tester::Utils
{

    template<typename T> inline void measure(const char* name, T&& fn)
    {
        auto start = std::chrono::high_resolution_clock::now();
        {
            _mm_pause();
            fn();
            _mm_pause();
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto dur = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(end - start);
        std::cout << "Execution (" << name << ") took : " << dur.count() << " ms."
                  << "\n";
    }

    std::string hexEncode(std::span<const uint8_t> bytes)
    {
        std::string out;
        out.reserve(bytes.size() * 2);

        constexpr const char* hexChars = "0123456789ABCDEF";
        for (const auto byte : bytes)
        {
            out.push_back(hexChars[byte >> 4]);
            out.push_back(hexChars[byte & 0xF]);
        }

        return out;
    }

    static std::vector<std::uint8_t> hexDecode(std::string_view hex)
    {
        const auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            return -1;
        };

        std::vector<std::uint8_t> out;
        out.reserve(hex.size() / 2);
        for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            const int hi = nibble(hex[i]);
            const int lo = nibble(hex[i + 1]);
            if (hi < 0 || lo < 0)
                break;
            out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
        }
        return out;
    }

    static bool iequals(std::string_view a, std::string_view b)
    {
        if (a.size() != b.size())
            return false;
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
                return false;
        }
        return true;
    }

    static std::optional<ZydisMnemonic> resolveMnemonic(std::string_view name)
    {
        for (int m = ZYDIS_MNEMONIC_INVALID + 1; m <= ZYDIS_MNEMONIC_MAX_VALUE; ++m)
        {
            if (iequals(name, ZydisMnemonicGetString(static_cast<ZydisMnemonic>(m))))
                return static_cast<ZydisMnemonic>(m);
        }
        return std::nullopt;
    }

    static std::optional<ZydisRegister> resolveRegister(std::string_view name)
    {
        for (int r = ZYDIS_REGISTER_NONE + 1; r <= ZYDIS_REGISTER_MAX_VALUE; ++r)
        {
            if (iequals(name, ZydisRegisterGetString(static_cast<ZydisRegister>(r))))
                return static_cast<ZydisRegister>(r);
        }
        return std::nullopt;
    }

    static std::optional<ZydisISAExt> resolveIsaExt(std::string_view name)
    {
        for (int i = 0; i <= ZYDIS_ISA_EXT_MAX_VALUE; ++i)
        {
            if (iequals(name, ZydisISAExtGetString(static_cast<ZydisISAExt>(i))))
                return static_cast<ZydisISAExt>(i);
        }
        return std::nullopt;
    }

    static std::optional<ZydisInstructionCategory> resolveCategory(std::string_view name)
    {
        for (int i = 0; i <= ZYDIS_CATEGORY_MAX_VALUE; ++i)
        {
            if (iequals(name, ZydisCategoryGetString(static_cast<ZydisInstructionCategory>(i))))
                return static_cast<ZydisInstructionCategory>(i);
        }
        return std::nullopt;
    }

} // namespace x86Tester::Utils
