#pragma once

#include <atomic>
#include <cstddef>
#include <iterator>
#include <thread>
#include <vector>

namespace x86Tester
{
    inline std::atomic<unsigned> g_maxThreads{ 0 };

    inline void setMaxThreads(unsigned n)
    {
        g_maxThreads.store(n, std::memory_order_relaxed);
    }

    template<typename Iterator, typename Func> void parallelForEach(Iterator first, Iterator last, Func fn)
    {
        const auto total = static_cast<std::size_t>(std::distance(first, last));
        if (total == 0)
            return;

        unsigned hw = std::thread::hardware_concurrency();
        if (hw == 0)
            hw = 1;

        const unsigned maxT = g_maxThreads.load(std::memory_order_relaxed);
        if (maxT != 0 && maxT < hw)
            hw = maxT;

        std::size_t workers = static_cast<std::size_t>(hw);
        if (workers > total)
            workers = total;

        if (workers <= 1)
        {
            for (auto it = first; it != last; ++it)
                fn(*it);
            return;
        }

        std::atomic<std::size_t> next{ 0 };

        std::vector<std::thread> threads;
        threads.reserve(workers);

        for (std::size_t w = 0; w < workers; ++w)
        {
            threads.emplace_back([first, total, &next, &fn]() {
                using diff = typename std::iterator_traits<Iterator>::difference_type;
                for (;;)
                {
                    const std::size_t i = next.fetch_add(1, std::memory_order_relaxed);
                    if (i >= total)
                        break;
                    fn(*std::next(first, static_cast<diff>(i)));
                }
            });
        }

        for (auto& t : threads)
            t.join();
    }

    template<typename Container, typename Func> void parallelForEach(Container&& container, Func fn)
    {
        parallelForEach(std::begin(container), std::end(container), std::move(fn));
    }

} // namespace x86Tester
