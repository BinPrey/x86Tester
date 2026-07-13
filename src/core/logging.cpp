#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fmt/format.h>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <x86Tester/logging.hpp>

#include "sysinfo.hpp"

#ifdef _WIN32
#    define WIN32_LEAN_AND_MEAN
#    define NOMINMAX
#    include <windows.h>
#else
#    include <limits.h>
#    include <unistd.h>
#endif

namespace x86Tester::Logging
{
    using clock = std::chrono::high_resolution_clock;

    namespace
    {
        std::filesystem::path exeDirectory()
        {
#ifdef _WIN32
            wchar_t buf[MAX_PATH];
            const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
            if (n == 0)
                return std::filesystem::current_path();
            return std::filesystem::path(std::wstring(buf, n)).parent_path();
#else
            char buf[PATH_MAX];
            const ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf));
            if (n <= 0)
                return std::filesystem::current_path();
            return std::filesystem::path(std::string(buf, static_cast<std::size_t>(n))).parent_path();
#endif
        }

        struct ProgressFrame
        {
            std::string name;
            double progress = 0.0;
            std::size_t depth = 0;
            clock::time_point startTime;
        };

        std::mutex g_mutex;
        std::ofstream g_logFile;
        bool g_logOpened = false;
        std::vector<ProgressFrame> g_stack;
        bool g_barActive = false;
        std::size_t g_barLen = 0;
        std::atomic<long long> g_nextReportTicks{ 0 };
        std::atomic<int> g_progressPct{ -1 };

        std::string indentFor(std::size_t depth)
        {
            return std::string(depth * 2, ' ');
        }

        void fileWrite(std::string_view line)
        {
            if (!g_logOpened)
            {
                g_logOpened = true;
                try
                {
                    g_logFile.open(exeDirectory() / "x86Tester.log", std::ios::out | std::ios::trunc);
                }
                catch (...)
                {
                }
            }
            if (g_logFile.is_open())
            {
                g_logFile << line << '\n';
                g_logFile.flush();
            }
        }

        void eraseBar()
        {
            if (!g_barActive)
                return;
            fmt::print("\r{:{}}\r", "", g_barLen);
            g_barActive = false;
            g_barLen = 0;
        }

        void drawBar()
        {
            if (g_stack.empty())
                return;

            constexpr const char* PBSTR = "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||";
            constexpr int PBWIDTH = 40;

            const auto& frame = g_stack.back();
            const int val = static_cast<int>(frame.progress * 100);
            const int lpad = static_cast<int>(frame.progress * PBWIDTH);

            std::string line = fmt::format("{}{:25} {:3d}% [{:40}]", indentFor(frame.depth), frame.name, val,
                std::string_view(PBSTR, static_cast<std::size_t>(lpad)));
            const std::size_t pad = line.size() < g_barLen ? g_barLen - line.size() : 0;
            fmt::print("\r{}{:{}}", line, "", pad);
            std::fflush(stdout);

            g_barLen = line.size();
            g_barActive = true;
        }

        void logLine(std::string_view line)
        {
            eraseBar();
            fmt::print("{}\n", line);
            drawBar();
            std::fflush(stdout);
        }

        bool colorEnabled()
        {
            static const bool enabled = []() {
                if (const char* nc = std::getenv("NO_COLOR"); nc != nullptr && nc[0] != '\0')
                    return false;
#ifdef _WIN32
                const HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
                if (h == INVALID_HANDLE_VALUE || h == nullptr)
                    return false;
                DWORD mode = 0;
                if (!GetConsoleMode(h, &mode))
                    return false;
                SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                return true;
#else
                return isatty(STDOUT_FILENO) != 0;
#endif
            }();
            return enabled;
        }

        void logLineColored(std::string_view line, std::string_view color)
        {
            eraseBar();
            if (colorEnabled())
                fmt::print("{}{}\x1b[0m\n", color, line);
            else
                fmt::print("{}\n", line);
            drawBar();
            std::fflush(stdout);
        }
    } // namespace

    void updateProgress(size_t val, size_t max)
    {
        g_progressPct.store(max != 0 ? static_cast<int>(100 * val / max) : 0, std::memory_order_relaxed);

        const auto now = clock::now();
        if (now.time_since_epoch().count() < g_nextReportTicks.load(std::memory_order_relaxed))
            return;

        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_stack.empty())
            return;

        using namespace std::chrono_literals;
        g_nextReportTicks.store((now + 50ms).time_since_epoch().count(), std::memory_order_relaxed);
        g_stack.back().progress = max != 0 ? static_cast<double>(val) / static_cast<double>(max) : 0.0;
        drawBar();
    }

    void endProgress()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_stack.empty())
            return;

        const ProgressFrame frame = g_stack.back();
        g_stack.pop_back();
        g_progressPct.store(
            g_stack.empty() ? -1 : static_cast<int>(g_stack.back().progress * 100), std::memory_order_relaxed);

        const auto seconds = std::chrono::duration<double>(clock::now() - frame.startTime).count();
        const std::string line = fmt::format("{}{}, completed in {:.2f}s.", indentFor(frame.depth), frame.name, seconds);

        logLine(line);
        fileWrite(line);
    }

    namespace Detail
    {
        void println(const std::string_view msg)
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            const std::size_t depth = g_stack.empty() ? 0 : g_stack.back().depth;
            const std::string line = fmt::format("{}{}", indentFor(depth), msg);
            logLine(line);
            fileWrite(line);
        }

        void error(const std::string_view msg)
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            const std::size_t depth = g_stack.empty() ? 0 : g_stack.back().depth;
            const std::string line = fmt::format("{}{}", indentFor(depth), msg);
            logLineColored(line, "\x1b[31m");
            fileWrite(line);
        }

        void startProgress(const std::string_view msg)
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            const std::size_t depth = g_stack.size();

            fileWrite(fmt::format("{}{}", indentFor(depth), msg));

            eraseBar();

            ProgressFrame frame;
            frame.name = std::string{ msg };
            frame.depth = depth;
            frame.startTime = clock::now();
            g_stack.push_back(std::move(frame));

            g_progressPct.store(0, std::memory_order_relaxed);
            drawBar();
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

    void setLogPath(std::string_view path)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_logFile.open(std::filesystem::path(path), std::ios::out | std::ios::trunc);
        g_logOpened = true;
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

                const int pct = g_progressPct.load();
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
