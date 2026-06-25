#include <atomic>
#include <chrono>
#include <fmt/format.h>
#include <mutex>
#include <string>
#include <thread>
#include <x86Tester/logging.hpp>

#include "sysinfo.hpp"

namespace x86Tester::Logging
{
    using clock = std::chrono::high_resolution_clock;

    static int _lastProgress = -1;
    static bool _inProgress = false;
    static std::string _progressName;
    static auto _nextReport = clock::now();
    static double _progress = 0.0;
    static size_t _progressLineLen = 0;
    static clock::time_point _startTime;
    static std::atomic<int> _progressPct{ -1 };

    static void printProgress(std::string_view name, double percentage, bool forcePrint)
    {
        using namespace std::chrono_literals;

        constexpr const char* PBSTR = "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||";
        constexpr int PBWIDTH = 40;

        int val = static_cast<int>(percentage * 100);
        if (val == _lastProgress && !forcePrint)
            return;

        auto now = clock::now();
        if (percentage != 1.0 && now < _nextReport && !forcePrint)
            return;

        _nextReport = now + 50ms;

        int lpad = static_cast<int>(percentage * PBWIDTH);
        int rpad = PBWIDTH - lpad;
        _lastProgress = val;

        int namepad = 20 - static_cast<int>(name.size());

        std::string line;
        line = fmt::format("\r{:25} {:3d}% [{:40}]", name, val, std::string_view(PBSTR, lpad));

        fmt::print("{}", line);
        std::fflush(stdout);

        _progressLineLen = line.size();
    }

    void updateProgress(size_t val, size_t max)
    {
        _progress = static_cast<double>(val) / max;
        _progressPct.store(max != 0 ? static_cast<int>(100 * val / max) : 0);
        printProgress(_progressName, _progress, false);
    }

    void endProgress()
    {
        _inProgress = false;
        _progressPct.store(-1);

        auto endTime = clock::now();
        auto seconds = std::chrono::duration<double>(endTime - _startTime).count();
        fmt::println(
            "\r{}, completed in {:.2f}s.{:{}}", _progressName, seconds, "",
            _progressName.size() < 72 ? 72 - _progressName.size() : 1);
    }

    namespace Detail
    {
        void println(const std::string_view msg)
        {
            if (_inProgress)
            {
                size_t spaces = msg.size() < _progressLineLen ? _progressLineLen - msg.size() : 0;
                fmt::println("\r{}{}", msg, std::string(spaces, ' '));
                printProgress(_progressName, _progress, true);
            }
            else
                fmt::println("{}", msg);
        }

        void startProgress(const std::string_view msg)
        {
            _progressName = std::string{ msg };
            _inProgress = true;
            _lastProgress = -1;
            _progress = 0.0;
            _progressPct.store(0);
            _startTime = clock::now();
            printProgress(_progressName, _progress, true);
        }

    } // namespace Detail

    static std::thread _titleThread;
    static std::atomic<bool> _titleRunning{ false };
    static std::mutex _titleStatusMutex;
    static std::string _titleStatus;
    static std::atomic<size_t> _titleCases{ 0 };
    static clock::time_point _titleStart;

    static std::string formatDuration(double seconds)
    {
        const auto total = static_cast<long long>(seconds);
        const long long h = total / 3600;
        const long long m = (total % 3600) / 60;
        const long long s = total % 60;
        if (h > 0)
            return fmt::format("{}:{:02}:{:02}", h, m, s);
        return fmt::format("{}:{:02}", m, s);
    }

    static std::string formatCount(size_t n)
    {
        if (n >= 1'000'000)
            return fmt::format("{:.1f}M", static_cast<double>(n) / 1'000'000.0);
        if (n >= 1'000)
            return fmt::format("{:.1f}k", static_cast<double>(n) / 1'000.0);
        return fmt::format("{}", n);
    }

    void setConsoleTitle(std::string_view title)
    {
        Detail::setConsoleTitleRaw(title);
    }

    void setTitleStatus(std::string_view status)
    {
        std::lock_guard<std::mutex> lock(_titleStatusMutex);
        _titleStatus.assign(status);
    }

    void addTitleCases(size_t n)
    {
        _titleCases.fetch_add(n, std::memory_order_relaxed);
    }

    void startTitleMonitor()
    {
        if (_titleRunning.exchange(true))
            return;

        _titleCases.store(0);
        _titleStart = clock::now();

        _titleThread = std::thread([]() {
            Detail::sampleCpuUsage();

            while (_titleRunning.load())
            {
                for (int i = 0; i < 10 && _titleRunning.load(); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (!_titleRunning.load())
                    break;

                const double cpu = Detail::sampleCpuUsage();
                const auto temp = Detail::readCpuTemp();

                std::string status;
                {
                    std::lock_guard<std::mutex> lock(_titleStatusMutex);
                    status = _titleStatus;
                }

                std::string title = fmt::format("x86Tester | CPU {:.0f}%", cpu);
                if (temp.has_value())
                    title += fmt::format(" {:.0f}°C", *temp);
                if (!status.empty())
                    title += " | " + status;

                const int pct = _progressPct.load();
                if (pct >= 0)
                    title += fmt::format(" {}%", pct);

                const auto secs = std::chrono::duration<double>(clock::now() - _titleStart).count();
                title += fmt::format(" | {} cases | {}", formatCount(_titleCases.load()), formatDuration(secs));

                Detail::setConsoleTitleRaw(title);
            }
        });
    }

    void stopTitleMonitor()
    {
        if (!_titleRunning.exchange(false))
            return;
        if (_titleThread.joinable())
            _titleThread.join();
    }

} // namespace x86Tester::Logging