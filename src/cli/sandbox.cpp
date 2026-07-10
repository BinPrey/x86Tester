#include "cli.hpp"

#ifdef _WIN32
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#    include <Windows.h>
#else
#    include <unistd.h>
#endif

namespace x86Tester
{
    int runSandbox()
    {
#ifdef _WIN32
        for (;;)
            SleepEx(INFINITE, TRUE);
#else
        for (;;)
            pause();
#endif
        return 0;
    }
} // namespace x86Tester
