#pragma once

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <thread>
#include <vector>

namespace x86Tester
{
    template<typename Iterator, typename Func> void parallelForEach(Iterator first, Iterator last, Func fn)
    {
        const auto total = static_cast<std::size_t>(std::distance(first, last));
        if (total == 0)
            return;

        unsigned hw = std::thread::hardware_concurrency();
        if (hw == 0)
            hw = 1;

        std::size_t workers = static_cast<std::size_t>(hw);
        if (workers > total)
            workers = total;

        if (workers <= 1)
        {
            for (auto it = first; it != last; ++it)
                fn(*it);
            return;
        }

        const std::size_t chunk = (total + workers - 1) / workers;

        std::vector<std::thread> threads;
        threads.reserve(workers);

        for (std::size_t begin = 0; begin < total; begin += chunk)
        {
            const std::size_t end = (begin + chunk < total) ? (begin + chunk) : total;
            threads.emplace_back([first, begin, end, &fn]() {
                Iterator it = first;
                std::advance(it, static_cast<typename std::iterator_traits<Iterator>::difference_type>(begin));
                for (std::size_t i = begin; i < end; ++i, ++it)
                    fn(*it);
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
