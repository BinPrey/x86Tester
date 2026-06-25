#include "sysinfo.hpp"

#include <cstdint>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#    define NOMINMAX
#endif
#include <Windows.h>

#include <Wbemidl.h>
#include <comdef.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace x86Tester::Logging::Detail
{
    void setConsoleTitleRaw(std::string_view title)
    {
        const int wlen = MultiByteToWideChar(CP_UTF8, 0, title.data(), static_cast<int>(title.size()), nullptr, 0);
        if (wlen <= 0)
            return;

        std::wstring wide(static_cast<std::size_t>(wlen), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, title.data(), static_cast<int>(title.size()), wide.data(), wlen);
        SetConsoleTitleW(wide.c_str());
    }

    static std::uint64_t fileTimeToU64(const FILETIME& ft)
    {
        ULARGE_INTEGER value;
        value.LowPart = ft.dwLowDateTime;
        value.HighPart = ft.dwHighDateTime;
        return value.QuadPart;
    }

    double sampleCpuUsage()
    {
        static std::uint64_t prevIdle = 0;
        static std::uint64_t prevTotal = 0;
        static bool primed = false;

        FILETIME idleFt, kernelFt, userFt;
        if (!GetSystemTimes(&idleFt, &kernelFt, &userFt))
            return 0.0;

        const std::uint64_t idle = fileTimeToU64(idleFt);
        const std::uint64_t total = fileTimeToU64(kernelFt) + fileTimeToU64(userFt);

        if (!primed)
        {
            prevIdle = idle;
            prevTotal = total;
            primed = true;
            return 0.0;
        }

        const std::uint64_t idleDelta = idle - prevIdle;
        const std::uint64_t totalDelta = total - prevTotal;
        prevIdle = idle;
        prevTotal = total;

        if (totalDelta == 0)
            return 0.0;

        const double busy = static_cast<double>(totalDelta - idleDelta);
        return busy * 100.0 / static_cast<double>(totalDelta);
    }

    static IWbemServices* connectThermalWmi()
    {
        static IWbemServices* services = []() -> IWbemServices* {
            const HRESULT init = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            if (FAILED(init) && init != RPC_E_CHANGED_MODE)
                return nullptr;

            CoInitializeSecurity(
                nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE,
                nullptr);

            IWbemLocator* locator = nullptr;
            if (FAILED(CoCreateInstance(
                    CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                    reinterpret_cast<void**>(&locator)))
                || locator == nullptr)
                return nullptr;

            IWbemServices* svc = nullptr;
            const HRESULT connected = locator->ConnectServer(
                _bstr_t(L"ROOT\\WMI"), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
            locator->Release();
            if (FAILED(connected) || svc == nullptr)
                return nullptr;

            CoSetProxyBlanket(
                svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr, EOAC_NONE);
            return svc;
        }();
        return services;
    }

    std::optional<double> readCpuTemp()
    {
        IWbemServices* services = connectThermalWmi();
        if (services == nullptr)
            return std::nullopt;

        IEnumWbemClassObject* enumerator = nullptr;
        if (FAILED(services->ExecQuery(
                _bstr_t(L"WQL"), _bstr_t(L"SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumerator))
            || enumerator == nullptr)
            return std::nullopt;

        std::optional<double> result;
        IWbemClassObject* obj = nullptr;
        ULONG returned = 0;
        if (SUCCEEDED(enumerator->Next(WBEM_INFINITE, 1, &obj, &returned)) && returned > 0 && obj != nullptr)
        {
            VARIANT value;
            VariantInit(&value);
            if (SUCCEEDED(obj->Get(L"CurrentTemperature", 0, &value, nullptr, nullptr)))
            {
                long tenthsKelvin = 0;
                if (value.vt == VT_I4)
                    tenthsKelvin = value.lVal;
                else if (value.vt == VT_UI4)
                    tenthsKelvin = static_cast<long>(value.ulVal);

                if (tenthsKelvin > 0)
                    result = static_cast<double>(tenthsKelvin) / 10.0 - 273.15;
            }
            VariantClear(&value);
            obj->Release();
        }
        enumerator->Release();
        return result;
    }
}
