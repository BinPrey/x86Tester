#pragma once

#include <chrono>
#include <cstdio>
#ifdef _WIN32
#    include <intrin.h>
#else
#    include <immintrin.h>
#endif
#include <iostream>
#include <fmt/format.h>
#include <span>

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

} // namespace x86Tester::Utils
