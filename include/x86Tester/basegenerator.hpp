#pragma once

#include <cassert>
#include <span>

namespace x86Tester::Generator
{
    template<typename T> struct BaseGenerator
    {
        std::span<const T> _choices;
        size_t _index{};

        BaseGenerator(std::span<const T> choices)
            : _choices(choices)
        {
        }

        T current() const
        {
            assert(_index < _choices.size());
            return _choices[_index];
        }

        bool advance()
        {
            _index++;
            if (_index < _choices.size())
                return true;

            _index = 0;
            return false;
        }
    };

} // namespace x86Tester::Generator