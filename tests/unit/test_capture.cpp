#include <thread>
#include <vector>

#include "check.hpp"
#include "inapparency/capture_ring.hpp"
#include "inapparency/channel_hopper.hpp"

using namespace inapparency;

namespace {

std::vector<std::uint8_t> bytes_of(std::size_t n, std::uint8_t fill) {
    return std::vector<std::uint8_t>(n, fill);
}

} // namespace

TEST(ring_push_front_release) {
    CaptureRing<4, 64> ring;
    Observation obs;
    CHECK(!ring.front(obs));

    auto frame = bytes_of(10, 0xab);
    CaptureMetadata meta;
    meta.timestamp_ms = 123;
    meta.channel = 6;
    meta.rssi_dbm = -40;
    meta.original_length = 10;
    meta.includes_fcs = true;
    CHECK(ring.push(frame, meta));
    CHECK_EQ(ring.size(), 1U);

    CHECK(ring.front(obs));
    CHECK_EQ(obs.timestamp_ms, 123U);
    CHECK_EQ(obs.bytes.size(), 10U);
    CHECK_EQ(obs.bytes[9], 0xab);
    CHECK(obs.channel == std::uint8_t{6});
    CHECK(obs.rssi_dbm == std::int8_t{-40});
    CHECK(obs.original_length == std::size_t{10});
    CHECK(obs.includes_fcs);

    ring.release();
    CHECK_EQ(ring.size(), 0U);
    CHECK(!ring.front(obs));
    ring.release(); // releasing an empty ring is harmless
    CHECK_EQ(ring.size(), 0U);
}

TEST(ring_keeps_order) {
    CaptureRing<8, 32> ring;
    for (std::uint8_t i = 0; i < 5; ++i) {
        CaptureMetadata meta;
        meta.timestamp_ms = i;
        ring.push(bytes_of(1, i), meta);
    }
    for (std::uint8_t i = 0; i < 5; ++i) {
        Observation obs;
        CHECK(ring.front(obs));
        CHECK_EQ(obs.timestamp_ms, i);
        CHECK_EQ(obs.bytes[0], i);
        ring.release();
    }
}

TEST(ring_drops_when_full_and_counts) {
    CaptureRing<4, 32> ring;
    for (int i = 0; i < 6; ++i) {
        ring.push(bytes_of(3, 1), {});
    }
    CHECK_EQ(ring.size(), 4U);
    CHECK_EQ(ring.dropped(), 2U);
    CHECK_EQ(ring.high_water(), 4U);
}

TEST(ring_cuts_long_frames_and_says_so) {
    CaptureRing<4, 32> ring;
    auto big = bytes_of(100, 7);
    CaptureMetadata meta;
    meta.includes_fcs = true;
    ring.push(big, meta);

    Observation obs;
    CHECK(ring.front(obs));
    CHECK_EQ(obs.bytes.size(), 32U);
    CHECK(obs.original_length == std::size_t{100});
}

TEST(ring_wraps_many_times) {
    CaptureRing<4, 32> ring;
    for (std::uint32_t i = 0; i < 10'000; ++i) {
        CaptureMetadata meta;
        meta.timestamp_ms = i;
        CHECK(ring.push(bytes_of(2, 0), meta));
        Observation obs;
        CHECK(ring.front(obs) && obs.timestamp_ms == i);
        ring.release();
    }
    CHECK_EQ(ring.dropped(), 0U);
}

TEST(ring_two_threads) {
    // Producer and consumer on different threads, like radio callback and
    // processing task. Every frame either arrives in order or is counted as
    // dropped.
    static CaptureRing<16, 32> ring;
    constexpr std::uint32_t kFrames = 200'000;

    std::thread producer([] {
        for (std::uint32_t i = 0; i < kFrames; ++i) {
            CaptureMetadata meta;
            meta.timestamp_ms = i;
            std::uint8_t b = static_cast<std::uint8_t>(i);
            ring.push(std::span<const std::uint8_t>(&b, 1), meta);
        }
    });

    std::uint64_t received = 0;
    std::int64_t last = -1;
    bool in_order = true;
    bool payload_ok = true;
    while (received + ring.dropped() < kFrames) {
        Observation obs;
        if (ring.front(obs)) {
            auto t = static_cast<std::int64_t>(obs.timestamp_ms);
            in_order = in_order && t > last;
            payload_ok = payload_ok && obs.bytes[0] == static_cast<std::uint8_t>(t);
            last = t;
            ++received;
            ring.release();
        }
    }
    producer.join();

    CHECK(in_order);
    CHECK(payload_ok);
    CHECK_EQ(received + ring.dropped(), kFrames);
}

TEST(hopper_default_is_1_6_11) {
    ChannelHopper h;
    CHECK(h.poll(0) == std::uint8_t{1});
    CHECK(!h.poll(100));
    CHECK(h.poll(500) == std::uint8_t{6});
    CHECK(h.poll(1000) == std::uint8_t{11});
    CHECK(h.poll(1500) == std::uint8_t{1});
}

TEST(hopper_tracks_time_per_channel) {
    ChannelHopper h;
    std::uint8_t list[] = {1, 6};
    CHECK(h.configure(list, 200));
    for (std::uint64_t t = 0; t <= 2000; t += 10) {
        h.poll(t);
    }
    CHECK_EQ(h.time_on(1, 2000) + h.time_on(6, 2000), 2000U);
    CHECK(h.time_on(1, 2000) >= 800 && h.time_on(1, 2000) <= 1200);
    CHECK_EQ(h.time_on(11, 2000), 0U);
}

TEST(hopper_lock_and_unlock) {
    ChannelHopper h;
    CHECK(h.poll(0) == std::uint8_t{1});
    CHECK(h.lock(9));
    CHECK(h.poll(10) == std::uint8_t{9});
    CHECK(!h.poll(100'000));
    CHECK(h.current() == std::uint8_t{9});
    CHECK(!h.lock(15));
    h.unlock();
    CHECK(h.poll(100'000).has_value());
}

TEST(hopper_single_channel_never_switches) {
    ChannelHopper h;
    std::uint8_t list[] = {6};
    CHECK(h.configure(list, 100));
    CHECK(h.poll(0) == std::uint8_t{6});
    for (std::uint64_t t = 0; t < 5000; t += 50) {
        CHECK(!h.poll(t + 1));
    }
    CHECK_EQ(h.time_on(6, 5000), 5000U);
}

TEST(hopper_rejects_bad_config) {
    ChannelHopper h;
    std::uint8_t bad[] = {1, 0};
    std::uint8_t too_high[] = {15};
    std::uint8_t ok[] = {3};
    CHECK(!h.configure(bad, 500));
    CHECK(!h.configure(too_high, 500));
    CHECK(!h.configure(ok, 10));
    CHECK(!h.configure(std::span<const std::uint8_t>{}, 500));
    CHECK_EQ(h.channels().size(), 3U); // kept 1,6,11
}

TEST(hopper_time_going_backwards) {
    ChannelHopper h;
    h.poll(1000);
    CHECK(!h.poll(10)); // clock jumped back: stay put, no underflow
    CHECK(h.time_on(1, 10) < 1000);
}

TEST(channel_list_parsing) {
    std::array<std::uint8_t, 14> out{};
    CHECK(parse_channel_list("1,6,11", out) == std::size_t{3});
    CHECK(out[0] == 1 && out[1] == 6 && out[2] == 11);
    CHECK(parse_channel_list(" 3 , 9 ", out) == std::size_t{2});
    CHECK(parse_channel_list("6,6,6", out) == std::size_t{1});
    CHECK(parse_channel_list("14", out) == std::size_t{1});

    CHECK(!parse_channel_list("", out));
    CHECK(!parse_channel_list("0", out));
    CHECK(!parse_channel_list("15", out));
    CHECK(!parse_channel_list("1,,6", out));
    CHECK(!parse_channel_list("1,6,", out));
    CHECK(!parse_channel_list("1;6", out));
    CHECK(!parse_channel_list("abc", out));
    CHECK(!parse_channel_list("1000", out));

    std::array<std::uint8_t, 2> small{};
    CHECK(!parse_channel_list("1,2,3", small));
}
