#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <iterator>
#include <mutex>
#include <thread>
#include <vector>

namespace x86Tester
{
    inline std::atomic<unsigned> g_maxThreads{ 0 };

    inline void setMaxThreads(unsigned n)
    {
        g_maxThreads.store(n, std::memory_order_relaxed);
    }

    class ThreadPool
    {
        std::vector<std::thread> _workers;
        std::mutex _mtx;
        std::condition_variable _wake;
        std::condition_variable _done;
        std::function<void(std::size_t)> _job;
        std::size_t _total = 0;
        std::atomic<std::size_t> _next{ 0 };
        std::size_t _generation = 0;
        std::size_t _active = 0;
        bool _stop = false;

    public:
        explicit ThreadPool(std::size_t workers)
        {
            for (std::size_t w = 0; w < workers; ++w)
                _workers.emplace_back([this] { workerLoop(); });
        }

        ~ThreadPool()
        {
            {
                std::lock_guard lock(_mtx);
                _stop = true;
            }
            _wake.notify_all();
            for (auto& t : _workers)
                t.join();
        }

        std::size_t size() const
        {
            return _workers.size();
        }

        void run(std::function<void(std::size_t)> job, std::size_t total)
        {
            std::unique_lock lock(_mtx);
            _job = std::move(job);
            _total = total;
            _next.store(0, std::memory_order_relaxed);
            _active = _workers.size();
            ++_generation;
            _wake.notify_all();
            _done.wait(lock, [this] { return _active == 0; });
            _job = nullptr;
        }

    private:
        void workerLoop()
        {
            std::size_t seen = 0;
            for (;;)
            {
                std::unique_lock lock(_mtx);
                _wake.wait(lock, [this, &seen] { return _stop || _generation != seen; });
                if (_stop)
                    return;
                seen = _generation;
                lock.unlock();

                for (;;)
                {
                    const std::size_t i = _next.fetch_add(1, std::memory_order_relaxed);
                    if (i >= _total)
                        break;
                    _job(i);
                }

                lock.lock();
                if (--_active == 0)
                    _done.notify_one();
            }
        }
    };

    inline ThreadPool& threadPool()
    {
        static ThreadPool instance([] {
            unsigned hw = std::thread::hardware_concurrency();
            if (hw == 0)
                hw = 1;
            if (hw > 32)
                hw = 32;
            const unsigned maxT = g_maxThreads.load(std::memory_order_relaxed);
            if (maxT != 0)
            {
                // User specified amount.
                hw = maxT;
            }
            else
            {
                // Keep 1 core available for the system and other tasks.
                hw = std::max(1u, hw - 1);
            }

            return static_cast<std::size_t>(hw);
        }());
        return instance;
    }

    template<typename Iterator, typename Func> void parallelForEach(Iterator first, Iterator last, Func fn)
    {
        const auto total = static_cast<std::size_t>(std::distance(first, last));
        if (total == 0)
            return;

        auto& pool = threadPool();
        if (pool.size() <= 1 || total == 1)
        {
            for (auto it = first; it != last; ++it)
                fn(*it);
            return;
        }

        using diff = typename std::iterator_traits<Iterator>::difference_type;
        pool.run([&](std::size_t i) { fn(*std::next(first, static_cast<diff>(i))); }, total);
    }

    template<typename Container, typename Func> void parallelForEach(Container&& container, Func fn)
    {
        parallelForEach(std::begin(container), std::end(container), std::move(fn));
    }

} // namespace x86Tester
