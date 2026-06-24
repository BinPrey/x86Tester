#include <chrono>
#include <print>
#include <x86Tester/logging.hpp>

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
        line = std::format("\r{:25} {:3d}% [{:40}]", name, val, std::string_view(PBSTR, lpad));

        std::print("{}", line);
        std::fflush(stdout);

        _progressLineLen = line.size();
    }

    void updateProgress(size_t val, size_t max)
    {
        _progress = static_cast<double>(val) / max;
        printProgress(_progressName, _progress, false);
    }

    void endProgress()
    {
        _inProgress = false;

        auto endTime = clock::now();
        auto seconds = std::chrono::duration<double>(endTime - _startTime).count();
        std::println(
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
                std::println("\r{}{}", msg, std::string(spaces, ' '));
                printProgress(_progressName, _progress, true);
            }
            else
                std::println("{}", msg);
        }

        void startProgress(const std::string_view msg)
        {
            _progressName = std::string{ msg };
            _inProgress = true;
            _lastProgress = -1;
            _progress = 0.0;
            _startTime = clock::now();
            printProgress(_progressName, _progress, true);
        }

    } // namespace Detail

} // namespace x86Tester::Logging