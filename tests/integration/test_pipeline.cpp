// Full pipeline runs over longer synthetic captures: a quiet minute of
// ordinary traffic, then an attack.

#include "check.hpp"
#include "inapparency/rules/deauth_burst.hpp"
#include "inapparency/rules/malformed_frames.hpp"
#include "scenario.hpp"

using namespace inapparency;
using namespace testing;

namespace {

const MacAddress kHome = mac(0x02, 0x10, 0x10, 0x10, 0x10, 0x10);
const MacAddress kNeighbor = mac(0x02, 0x20, 0x20, 0x20, 0x20, 0x20);
const MacAddress kCafe = mac(0x02, 0x30, 0x30, 0x30, 0x30, 0x30);

struct Pipeline {
    rules::DeauthBurstRule deauth_rule;
    rules::MalformedFramesRule malformed_rule;
    Detector detector;
    Scenario scenario{detector};

    Pipeline() {
        detector.add_rule(deauth_rule);
        detector.add_rule(malformed_rule);
    }
};

// A minute of an ordinary apartment: three APs beaconing, phones probing,
// data flowing, and the odd client leaving.
void quiet_minute(Pipeline& p, std::uint64_t start) {
    auto data = FrameBuilder(ManagementSubtype::Beacon).type(2).raw_subtype(8).build();
    auto probe = FrameBuilder(ManagementSubtype::ProbeRequest)
                     .transmitter(kClient)
                     .bssid(kBroadcast)
                     .ssid("")
                     .build();
    for (std::uint64_t t = start; t < start + 60'000; t += 100) {
        p.scenario.feed(beacon(kHome, Security::Wpa3PmfRequired, 6), t);
        p.scenario.feed(beacon(kNeighbor, Security::Wpa2NoPmf, 6), t + 30);
        p.scenario.feed(beacon(kCafe, Security::Open, 6), t + 60);
        p.scenario.feed(data, t + 10);
        if ((t - start) % 2000 == 0) {
            p.scenario.feed(probe, t + 20);
        }
        if ((t - start) % 15'000 == 0) {
            p.scenario.feed(disassoc(kNeighbor, kClient, 8), t + 40); // client leaving
        }
    }
}

} // namespace

TEST(pipeline_quiet_minute_has_no_events) {
    Pipeline p;
    quiet_minute(p, 0);
    CHECK(p.scenario.sink.events.empty());
    CHECK_EQ(p.detector.context().network_count(), 3U);

    const auto* home = p.detector.context().network(kHome);
    CHECK(home && home->pmf_required_seen);
    CHECK(home && home->ssid && home->ssid->view() == "lab");
    CHECK(home && home->channel == std::uint8_t{6});
    CHECK(p.detector.context().network(kCafe) && !p.detector.context().network(kCafe)->rsn);
}

TEST(pipeline_attack_after_quiet_minute) {
    Pipeline p;
    quiet_minute(p, 0);
    for (std::uint64_t i = 0; i < 200; ++i) {
        p.scenario.feed(deauth(kHome, kBroadcast, 7), 60'000 + i * 10);
    }

    CHECK_EQ(p.scenario.sink.count(rules::DeauthBurstRule::kId), 1U);
    CHECK_EQ(p.scenario.sink.count(rules::MalformedFramesRule::kId), 0U);
    const auto& e = p.scenario.sink.events.front();
    CHECK(e.bssid == kHome);
    // 35 base + 10 broadcast + 5 same reason + 25 unprotected on a PMF network
    CHECK_EQ(e.confidence, 75);
}

TEST(pipeline_stats_add_up) {
    Pipeline p;
    p.scenario.feed(beacon(kHome, Security::Open), 0);
    p.scenario.feed(FrameBuilder(ManagementSubtype::Beacon).type(1).raw_subtype(13).build(), 1);
    p.scenario.feed({}, 2);
    p.scenario.feed(FrameBuilder(ManagementSubtype::Deauthentication).build(), 3);
    p.scenario.feed(FrameBuilder(ManagementSubtype::Beacon).version(3).build(), 4);
    auto cut = beacon(kHome, Security::Open);
    p.scenario.feed(cut, 5, 6, cut.size() + 10);

    const auto& s = p.detector.stats();
    CHECK_EQ(s.observations, 6U);
    CHECK_EQ(s.ok, 2U);
    CHECK_EQ(s.unsupported, 1U);
    CHECK_EQ(s.empty, 1U);
    CHECK_EQ(s.truncated, 1U);
    CHECK_EQ(s.bad_version, 1U);
    CHECK_EQ(s.capture_truncated, 1U);
    CHECK_EQ(s.events, 0U);
}

TEST(pipeline_is_deterministic) {
    auto run = [] {
        Pipeline p;
        quiet_minute(p, 0);
        for (std::uint64_t i = 0; i < 100; ++i) {
            p.scenario.feed(deauth(kNeighbor, kClient, 1), 60'000 + i * 30);
            p.scenario.feed(FrameBuilder(ManagementSubtype::Disassociation).build(),
                            60'000 + i * 30 + 1);
        }
        return p.scenario.sink.events;
    };
    auto a = run();
    auto b = run();
    CHECK_EQ(a.size(), 2U);
    CHECK_EQ(a.size(), b.size());
    for (std::size_t i = 0; i < a.size() && i < b.size(); ++i) {
        CHECK_EQ(a[i].rule_id, b[i].rule_id);
        CHECK_EQ(a[i].timestamp_ms, b[i].timestamp_ms);
        CHECK_EQ(a[i].confidence, b[i].confidence);
        CHECK_EQ(a[i].evidence_count, b[i].evidence_count);
    }
}

TEST(pipeline_duplicate_rule_ids_rejected) {
    rules::DeauthBurstRule a;
    rules::DeauthBurstRule b;
    Detector d;
    CHECK(d.add_rule(a));
    CHECK(!d.add_rule(b));
}
