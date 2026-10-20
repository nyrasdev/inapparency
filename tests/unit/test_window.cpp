#include "check.hpp"
#include "frame_builder.hpp"
#include "inapparency/mac_table.hpp"
#include "inapparency/rolling_counter.hpp"

using namespace inapparency;
using testing::mac;

TEST(counter_counts_inside_window) {
    RollingCounter<10> c(1000); // 100 ms buckets
    for (std::uint64_t t = 0; t < 500; t += 50) {
        CHECK(c.add(t));
    }
    CHECK_EQ(c.total(500), 10U);
    CHECK_EQ(c.window_ms(), 1000U);
}

TEST(counter_forgets_old_events) {
    RollingCounter<10> c(1000);
    c.add(0, 5);
    CHECK_EQ(c.total(900), 5U);
    CHECK_EQ(c.total(1000), 0U); // bucket 0 rolled out
    c.add(1000, 2);
    CHECK_EQ(c.total(1500), 2U);
}

TEST(counter_handles_big_time_jumps) {
    RollingCounter<10> c(1000);
    c.add(0, 3);
    CHECK_EQ(c.total(10'000'000), 0U);
    c.add(10'000'000);
    CHECK_EQ(c.total(10'000'000), 1U);
}

TEST(counter_out_of_order_inside_window_counts) {
    RollingCounter<10> c(1000);
    c.add(900);
    CHECK(c.add(500));
    CHECK_EQ(c.total(900), 2U);
}

TEST(counter_out_of_order_too_old_is_dropped) {
    RollingCounter<10> c(1000);
    c.add(5000);
    CHECK(!c.add(100));
    CHECK_EQ(c.total(5000), 1U);
}

TEST(counter_saturates_instead_of_wrapping) {
    RollingCounter<2> c(100);
    c.add(0, 0xFFFFFFF0U);
    c.add(0, 0x100U);
    CHECK_EQ(c.total(0), 0xFFFFFFFFU);
    c.add(60, 0xFFFFFFF0U);
    CHECK_EQ(c.total(60), 0xFFFFFFFFU);
}

TEST(counter_window_smaller_than_buckets_still_works) {
    RollingCounter<20> c(5); // bucket rounds up to 1 ms
    c.add(3);
    CHECK_EQ(c.total(3), 1U);
    CHECK_EQ(c.window_ms(), 20U);
}

TEST(table_inserts_and_finds) {
    MacTable<int, 4> t;
    bool inserted = false;
    t.touch(mac(0, 0, 0, 0, 0, 1), 10, inserted) = 42;
    CHECK(inserted);
    t.touch(mac(0, 0, 0, 0, 0, 1), 20, inserted);
    CHECK(!inserted);
    CHECK(t.find(mac(0, 0, 0, 0, 0, 1)) && *t.find(mac(0, 0, 0, 0, 0, 1)) == 42);
    CHECK(t.find(mac(0, 0, 0, 0, 0, 2)) == nullptr);
    CHECK_EQ(t.size(), 1U);
}

TEST(table_evicts_least_recently_touched) {
    MacTable<int, 3> t;
    bool inserted = false;
    t.touch(mac(0, 0, 0, 0, 0, 1), 10, inserted) = 1;
    t.touch(mac(0, 0, 0, 0, 0, 2), 20, inserted) = 2;
    t.touch(mac(0, 0, 0, 0, 0, 3), 30, inserted) = 3;
    t.touch(mac(0, 0, 0, 0, 0, 1), 40, inserted); // refresh 1
    t.touch(mac(0, 0, 0, 0, 0, 4), 50, inserted) = 4;

    CHECK(t.find(mac(0, 0, 0, 0, 0, 2)) == nullptr); // oldest went
    CHECK(t.find(mac(0, 0, 0, 0, 0, 1)) != nullptr);
    CHECK(t.find(mac(0, 0, 0, 0, 0, 4)) && *t.find(mac(0, 0, 0, 0, 0, 4)) == 4);
    CHECK_EQ(t.size(), 3U);
    CHECK_EQ(t.evictions(), 1U);
}

TEST(table_eviction_resets_value) {
    MacTable<int, 1> t;
    bool inserted = false;
    t.touch(mac(0, 0, 0, 0, 0, 1), 1, inserted) = 99;
    int& fresh = t.touch(mac(0, 0, 0, 0, 0, 2), 2, inserted);
    CHECK(inserted);
    CHECK_EQ(fresh, 0);
}

TEST(table_stays_bounded_under_churn) {
    MacTable<int, 8> t;
    bool inserted = false;
    for (std::uint32_t i = 0; i < 5000; ++i) {
        auto b = static_cast<std::uint8_t>(i & 0xff);
        auto c = static_cast<std::uint8_t>(i >> 8);
        t.touch(mac(2, 0, 0, 0, c, b), i, inserted);
    }
    CHECK_EQ(t.size(), 8U);
    CHECK_EQ(t.evictions(), 5000U - 8U);
}
