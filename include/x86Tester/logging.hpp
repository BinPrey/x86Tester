#pragma once

#include <fmt/format.h>

namespace x86Tester::Logging
{
    namespace Detail
    {
        void println(const std::string_view msg);
        void startProgress(const std::string_view msg);
    }

    template<typename... TArgs> void startProgress(const fmt::format_string<TArgs...> _Fmt, TArgs&&... args)
    {
        auto msg = fmt::format(_Fmt, std::forward<TArgs>(args)...);
        Detail::startProgress(msg);
    }

    void updateProgress(size_t val, size_t max);
    void endProgress();

    template<typename... TArgs> void println(const fmt::format_string<TArgs...> _Fmt, TArgs&&... args)
    {
        auto msg = fmt::format(_Fmt, std::forward<TArgs>(args)...);
        Detail::println(msg);
    }

} // namespace x86Tester::Logging