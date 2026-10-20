#include "check.hpp"
#include "inapparency/rules/malformed_frames.hpp"
#include "scenario.hpp"

using namespace inapparency;
using namespace testing;
using rules::MalformedFramesConfig;
using rules::MalformedFramesRule;

namespace {

struct Rig {
    MalformedFramesRule rule;
    Detector detector;
    Scenario scenario{detector};

    explicit Rig(const MalformedFramesConfig& config = {}) : rule(config) {
        detector.add_rule(rule);
    }
    std::size_t events() const { return scenario.sink.events.size(); }
};

// Deauth whose body is one byte short of a reason code.
std::vector<std::uint8_t> short_deauth() {
    return FrameBuilder(ManagementSubtype::Deauthentication).u8(7).build();
}

std::vector<std::uint8_t> bad_version() {
    return FrameBuilder(ManagementSubtype::Beacon).version(2).beacon_fixed().build();
}

std::vector<std::uint8_t> oversized_ssid_beacon() {
    FrameBuilder b(ManagementSubtype::Beacon);
    b.beacon_fixed().u8(0).u8(40);
    for (int i = 0; i < 40; ++i) {
        b.u8('x');
    }
    return b.build();
}

std::vector<std::uint8_t> overrunning_element_beacon() {
    return FrameBuilder(ManagementSubtype::Beacon).beacon_fixed().bytes({221, 50, 1, 2}).build();
}

} // namespace

TEST(malformed_a_few_are_ignored) {
    Rig rig;
    for (std::uint64_t i = 0; i < 9; ++i) {
        rig.scenario.feed(short_deauth(), i * 100);
    }
    CHECK_EQ(rig.events(), 0U);
}

TEST(malformed_flood_fires_low_severity) {
    Rig rig;
    for (std::uint64_t i = 0; i < 30; ++i) {
        rig.scenario.feed(i % 3 == 0   ? short_deauth()
                          : i % 3 == 1 ? bad_version()
                                       : oversized_ssid_beacon(),
                          i * 50);
    }
    CHECK_EQ(rig.events(), 1U);
    const auto& e = rig.scenario.sink.events.front();
    CHECK(e.severity == Severity::Low);
    CHECK_EQ(e.rule_id, MalformedFramesRule::kId);
    CHECK_EQ(e.evidence_count, 10U);
    CHECK(!e.bssid);
    CHECK(e.confidence >= 30 && e.confidence <= 60);
}

TEST(malformed_capture_truncation_does_not_count) {
    Rig rig;
    auto frame = short_deauth();
    for (std::uint64_t i = 0; i < 50; ++i) {
        rig.scenario.feed(frame, i * 10, 6, frame.size() + 100);
    }
    CHECK_EQ(rig.events(), 0U);
}

TEST(malformed_overrun_needs_known_length) {
    // Without original_length we can't tell a bad sender from a short capture.
    Rig unknown;
    auto frame = overrunning_element_beacon();
    for (std::uint64_t i = 0; i < 50; ++i) {
        unknown.scenario.feed(frame, i * 10);
    }
    CHECK_EQ(unknown.events(), 0U);

    Rig known;
    for (std::uint64_t i = 0; i < 50; ++i) {
        known.scenario.feed(frame, i * 10, 6, frame.size());
    }
    CHECK_EQ(known.events(), 1U);
}

TEST(malformed_ignores_unsupported_and_valid_frames) {
    Rig rig;
    auto data = FrameBuilder(ManagementSubtype::Beacon).type(2).raw_subtype(0).build();
    for (std::uint64_t i = 0; i < 100; ++i) {
        rig.scenario.feed(data, i);
        rig.scenario.feed(beacon(kAccessPoint, Security::Wpa2NoPmf), i);
        rig.scenario.feed({}, i);
    }
    CHECK_EQ(rig.events(), 0U);
}

TEST(malformed_cooldown) {
    Rig rig;
    for (std::uint64_t t = 0; t < 130'000; t += 100) {
        rig.scenario.feed(short_deauth(), t);
    }
    CHECK_EQ(rig.events(), 3U); // ~1 s, ~61 s, ~121 s
}

TEST(malformed_invalid_config) {
    MalformedFramesConfig config;
    config.window_ms = 1;
    CHECK(MalformedFramesRule(config).config_rejected());
}
