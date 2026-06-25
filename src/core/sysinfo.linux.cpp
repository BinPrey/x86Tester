#include "sysinfo.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

#include <unistd.h>

namespace x86Tester::Logging::Detail
{
    void setConsoleTitleRaw(std::string_view title)
    {
        std::string seq = "\x1b]0;";
        seq.append(title);
        seq.push_back('\x07');
        const auto written = ::write(STDOUT_FILENO, seq.data(), seq.size());
        (void)written;
    }

    double sampleCpuUsage()
    {
        static std::uint64_t prevIdle = 0;
        static std::uint64_t prevTotal = 0;
        static bool primed = false;

        std::FILE* file = std::fopen("/proc/stat", "r");
        if (file == nullptr)
            return 0.0;

        unsigned long long user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0;
        const int got = std::fscanf(
            file, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &user, &nice, &system, &idle, &iowait, &irq, &softirq,
            &steal);
        std::fclose(file);

        if (got < 4)
            return 0.0;

        const std::uint64_t idleAll = idle + iowait;
        const std::uint64_t total = user + nice + system + idleAll + irq + softirq + steal;

        if (!primed)
        {
            prevIdle = idleAll;
            prevTotal = total;
            primed = true;
            return 0.0;
        }

        const std::uint64_t idleDelta = idleAll - prevIdle;
        const std::uint64_t totalDelta = total - prevTotal;
        prevIdle = idleAll;
        prevTotal = total;

        if (totalDelta == 0)
            return 0.0;

        return static_cast<double>(totalDelta - idleDelta) * 100.0 / static_cast<double>(totalDelta);
    }

    static std::optional<double> readMilliCelsius(const char* path)
    {
        std::FILE* file = std::fopen(path, "r");
        if (file == nullptr)
            return std::nullopt;

        long milli = 0;
        const int got = std::fscanf(file, "%ld", &milli);
        std::fclose(file);

        if (got != 1)
            return std::nullopt;

        return static_cast<double>(milli) / 1000.0;
    }

    std::optional<double> readCpuTemp()
    {
        for (int i = 0; i < 32; ++i)
        {
            char namePath[128];
            std::snprintf(namePath, sizeof(namePath), "/sys/class/hwmon/hwmon%d/name", i);

            std::FILE* nameFile = std::fopen(namePath, "r");
            if (nameFile == nullptr)
                continue;

            char name[64] = {};
            const int got = std::fscanf(nameFile, "%63s", name);
            std::fclose(nameFile);
            if (got != 1)
                continue;

            const std::string_view view(name);
            if (view == "coretemp" || view == "k10temp" || view == "zenpower")
            {
                char tempPath[128];
                std::snprintf(tempPath, sizeof(tempPath), "/sys/class/hwmon/hwmon%d/temp1_input", i);
                if (auto temp = readMilliCelsius(tempPath))
                    return temp;
            }
        }

        return readMilliCelsius("/sys/class/thermal/thermal_zone0/temp");
    }
}
