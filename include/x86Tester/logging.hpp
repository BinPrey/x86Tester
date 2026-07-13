#pragma once

#include <fmt/format.h>
#include <string_view>
#include <utility>

namespace x86Tester::Logging
{
    namespace Detail
    {
        void println(const std::string_view msg);
        void warn(const std::string_view msg);
        void error(const std::string_view msg);
        void startProgress(const std::string_view msg);
    }

    template<typename... TArgs> void startProgress(const fmt::format_string<TArgs...> _Fmt, TArgs&&... args)
    {
        auto msg = fmt::format(_Fmt, std::forward<TArgs>(args)...);
        Detail::startProgress(msg);
    }

    void updateProgress(size_t val, size_t max);
    void endProgress();

    class ProgressReport
    {
    public:
        template<typename... TArgs> explicit ProgressReport(const fmt::format_string<TArgs...> _Fmt, TArgs&&... args)
        {
            Detail::startProgress(fmt::format(_Fmt, std::forward<TArgs>(args)...));
        }

        ProgressReport(const ProgressReport&) = delete;
        ProgressReport(ProgressReport&&) = delete;
        ProgressReport& operator=(const ProgressReport&) = delete;
        ProgressReport& operator=(ProgressReport&&) = delete;

        ~ProgressReport()
        {
            endProgress();
        }
    };

    template<typename... TArgs> void println(const fmt::format_string<TArgs...> _Fmt, TArgs&&... args)
    {
        auto msg = fmt::format(_Fmt, std::forward<TArgs>(args)...);
        Detail::println(msg);
    }

    template<typename... TArgs> void warn(const fmt::format_string<TArgs...> _Fmt, TArgs&&... args)
    {
        auto msg = fmt::format(_Fmt, std::forward<TArgs>(args)...);
        Detail::warn(msg);
    }

    template<typename... TArgs> void error(const fmt::format_string<TArgs...> _Fmt, TArgs&&... args)
    {
        auto msg = fmt::format(_Fmt, std::forward<TArgs>(args)...);
        Detail::error(msg);
    }

    void setLogPath(std::string_view path);

    void setConsoleTitle(std::string_view title);
    void setTitleStatus(std::string_view status);
    void addTitleCases(size_t n);
    void startTitleMonitor();
    void stopTitleMonitor();

} // namespace x86Tester::Logging