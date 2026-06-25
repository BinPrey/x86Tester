#include <x86Tester/parallel.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <numeric>
#include <vector>

TEST(Parallel, EmptyRange)
{
    std::vector<int> in;
    std::atomic<int> calls{ 0 };
    x86Tester::parallelForEach(in.begin(), in.end(), [&](int) { calls.fetch_add(1); });
    EXPECT_EQ(calls.load(), 0);
}

TEST(Parallel, SingleElement)
{
    std::vector<int> in{ 42 };
    std::atomic<long long> sum{ 0 };
    x86Tester::parallelForEach(in.begin(), in.end(), [&](int v) { sum.fetch_add(v); });
    EXPECT_EQ(sum.load(), 42);
}

TEST(Parallel, VisitsEachExactlyOnce)
{
    const std::size_t n = 100000;
    std::vector<int> in(n);
    std::iota(in.begin(), in.end(), 0);

    std::vector<std::atomic<int>> seen(n);
    for (auto& s : seen)
        s.store(0);

    x86Tester::parallelForEach(in.begin(), in.end(), [&](int v) { seen[static_cast<std::size_t>(v)].fetch_add(1); });

    for (std::size_t i = 0; i < n; ++i)
        ASSERT_EQ(seen[i].load(), 1) << "index " << i;
}

TEST(Parallel, SumMatchesSequential)
{
    std::vector<int> in(50000);
    std::iota(in.begin(), in.end(), 1);

    std::atomic<long long> sum{ 0 };
    x86Tester::parallelForEach(in.begin(), in.end(), [&](int v) { sum.fetch_add(v); });

    const long long expected = std::accumulate(in.begin(), in.end(), 0LL);
    EXPECT_EQ(sum.load(), expected);
}

TEST(Parallel, ContainerOverload)
{
    std::vector<int> in(1000);
    std::iota(in.begin(), in.end(), 0);

    std::atomic<int> calls{ 0 };
    x86Tester::parallelForEach(in, [&](int) { calls.fetch_add(1); });

    EXPECT_EQ(calls.load(), 1000);
}
