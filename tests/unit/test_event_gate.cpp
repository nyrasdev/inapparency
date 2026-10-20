#include "check.hpp"
#include "inapparency/event_gate.hpp"
#include "scenario.hpp"

using namespace inapparency;
using namespace testing;

namespace {

DetectionEvent event(std::uint32_t rule, std::uint64_t at, std::optional<MacAddress> bssid) {
    DetectionEvent e;
    e.rule_id = rule;
    e.timestamp_ms = at;
    e.bssid = bssid;
    return e;
}

MacAddress ap(std::uint32_t i) {
    return mac(2, 0, 0, static_cast<std::uint8_t>(i >> 8), static_cast<std::uint8_t>(i), 9);
}

} // namespace

TEST(gate_passes_first_event) {
    CollectingSink out;
    EventGate gate(out);
    gate.emit(event(1, 1000, kAccessPoint));
    CHECK_EQ(out.events.size(), 1U);
    CHECK_EQ(gate.stats().passed, 1U);
}

TEST(gate_drops_same_rule_same_bssid_inside_window) {
    CollectingSink out;
    EventGate gate(out);
    gate.emit(event(1, 0, kAccessPoint));
    gate.emit(event(1, 5000, kAccessPoint));
    gate.emit(event(1, 9999, kAccessPoint));
    CHECK_EQ(out.events.size(), 1U);
    CHECK_EQ(gate.stats().duplicates, 2U);

    gate.emit(event(1, 10'000, kAccessPoint)); // window over
    CHECK_EQ(out.events.size(), 2U);
}

TEST(gate_keeps_different_rules_and_networks_apart) {
    CollectingSink out;
    EventGate gate(out);
    gate.emit(event(1, 0, kAccessPoint));
    gate.emit(event(2, 0, kAccessPoint));
    gate.emit(event(1, 0, kClient));
    gate.emit(event(2, 0, std::nullopt));
    CHECK_EQ(out.events.size(), 4U);
    CHECK_EQ(gate.stats().duplicates, 0U);
}

TEST(gate_rate_limits_floods_and_counts_them) {
    CollectingSink out;
    EventGate gate(out); // burst 5, 20 per minute
    for (std::uint32_t i = 0; i < 100; ++i) {
        gate.emit(event(1, 1000, ap(i))); // 100 different BSSIDs at once
    }
    CHECK_EQ(out.events.size(), 5U);
    CHECK_EQ(gate.stats().rate_limited, 95U);
    CHECK_EQ(gate.stats().passed + gate.stats().suppressed(), 100U);
}

TEST(gate_refills_over_time) {
    CollectingSink out;
    EventGate gate(out);
    std::uint32_t n = 0;
    for (; n < 5; ++n) {
        gate.emit(event(1, 0, ap(n)));
    }
    gate.emit(event(1, 1000, ap(n++)));
    CHECK_EQ(out.events.size(), 5U); // 1 s isn't enough for a token at 20/min

    gate.emit(event(1, 3000, ap(n++)));
    CHECK_EQ(out.events.size(), 6U); // 3 s is

    // Over 10 minutes the long-run rate holds at about 20/min.
    for (std::uint64_t t = 3000; t < 603'000; t += 100) {
        gate.emit(event(1, t, ap(n++)));
    }
    CHECK(out.events.size() >= 195 && out.events.size() <= 210);
}

TEST(gate_slow_trickle_is_never_limited) {
    CollectingSink out;
    EventGate gate(out);
    for (std::uint32_t i = 0; i < 200; ++i) {
        gate.emit(event(1, i * 5000ULL, ap(i))); // 12 per minute, under 20
    }
    CHECK_EQ(out.events.size(), 200U);
}

TEST(gate_time_going_backwards) {
    CollectingSink out;
    EventGate gate(out);
    gate.emit(event(1, 50'000, kAccessPoint));
    gate.emit(event(1, 10'000, kAccessPoint));
    CHECK_EQ(out.events.size(), 1U);
    gate.emit(event(2, 10'000, kAccessPoint)); // different rule still passes
    CHECK_EQ(out.events.size(), 2U);
}

TEST(gate_recent_table_is_bounded) {
    CollectingSink out;
    EventGateConfig config;
    config.burst = 1000;
    config.max_per_minute = 6000;
    EventGate gate(out, config);
    for (std::uint32_t i = 0; i < 40; ++i) {
        gate.emit(event(1, i, ap(i)));
    }
    // ap(0) was pushed out of the 16-entry table, so it gets through again.
    gate.emit(event(1, 100, ap(0)));
    CHECK_EQ(out.events.size(), 41U);
}

TEST(gate_invalid_config) {
    CollectingSink out;
    EventGateConfig zero;
    zero.max_per_minute = 0;
    EventGate gate(out, zero);
    CHECK(gate.config_rejected());
    CHECK_EQ(gate.config().max_per_minute, EventGateConfig{}.max_per_minute);
    CHECK(!EventGate(out).config_rejected());
}
