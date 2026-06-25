#pragma once

#include <Zydis/SharedTypes.h>
#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>
#include <x86Tester/parallel.hpp>

namespace x86Tester
{
    struct InstructionEntries
    {
        // Instruction data is uint8_t len, uint8_t data[len]
        std::vector<uint8_t> instrData;

        // Offsets to the beginning of an entry.
        std::vector<uint32_t> entryOffsets;

        template<typename T> void forEach(T&& fn) const
        {
            for (size_t i = 0; i < entryOffsets.size(); ++i)
            {
                const auto entryOffset = entryOffsets[i];
                const auto length = instrData[entryOffset];
                const auto instrData = std::span<const uint8_t>(this->instrData.data() + entryOffset + 1, length);
                fn(instrData);
            }
        }

        template<typename T> void forEachParallel(T&& fn) const
        {
#ifndef _DEBUG
            parallelForEach(entryOffsets.begin(), entryOffsets.end(), [&](const auto entryOffset) {
                const auto length = instrData[entryOffset];
                const auto instrData = std::span<const uint8_t>(this->instrData.data() + entryOffset + 1, length);
                fn(instrData);
            });
#else
            forEach(std::forward<T>(fn));
#endif
        }
    };

} // namespace x86Tester