#pragma once

#include <optional>
#include <string_view>

namespace x86Tester::Logging::Detail
{
    void setConsoleTitleRaw(std::string_view title);

    double sampleCpuUsage();

    std::optional<double> readCpuTemp();
}
