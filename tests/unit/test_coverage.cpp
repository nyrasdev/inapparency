#include "check.hpp"
#include "inapparency/rules/deauth_burst.hpp"
#include "scenario.hpp"

using namespace inapparency;
using namespace testing;
using rules::DeauthBurstConfig;
using rules::DeauthBurstRule;

namespace {

struct Rig {
    DeauthBurstRule rule;
    Detector detector;
    Scenario scenario{detector};

    explicit Rig(const DeauthBurstConfig& config = {}) : rule(config) { detector.add_rule(rule); }
    const std::vector<DetectionEvent>& events() const { return scenario.sink.events; }
};

void hop_three(Detector& d) {
    for (std::uint8_t ch : {std::uint8_t{1}, std::uint8_t{6}, std::uint8_t{11}}) {
        d.set_channel_coverage(ch, 33);
    }
}

void deauths(Rig& rig, int n, std::uint64_t start = 0, std::uint8_t channel = 6) {
    for (int i = 0; i < n; ++i) {
        rig.scenario.feed(deauth(kAccessPoint, kBroadcast),
                          start + static_cast<std::uint64_t>(i) * 20, channel);
    }
}

} // namespace

TEST(coverage_defaults_to_full) {
    Detector d;
    CHECK_EQ(d.context().coverage(6), 100);
    CHECK_EQ(d.context().coverage(std::nullopt), 100);
    CHECK_EQ(d.context().coverage(200), 100);
}

TEST(coverage_ignores_bad_values) {
    Detector d;
    d.set_channel_coverage(6, 0);
    d.set_channel_coverage(6, 150);
    d.set_channel_coverage(99, 50);
    CHECK_EQ(d.context().coverage(6), 100);
    d.set_channel_coverage(6, 50);
    CHECK_EQ(d.context().coverage(6), 50);
}

TEST(hopping_scales_threshold_down) {
    // Full coverage: 7 frames is nothing.
    Rig fixed;
    deauths(fixed, 7);
    CHECK(fixed.events().empty());

    // A third of the time on channel: 7 seen ≈ 20 sent.
    Rig hopping;
    hop_three(hopping.detector);
    deauths(hopping, 6);
    CHECK(hopping.events().empty());
    deauths(hopping, 1, 200);
    CHECK_EQ(hopping.events().size(), 1U);
    CHECK(hopping.events().front().coverage_percent == std::uint8_t{33});
}

TEST(hopping_never_goes_below_min_threshold) {
    Rig rig;
    for (std::uint8_t ch = 1; ch <= 13; ++ch) {
        rig.detector.set_channel_coverage(ch, 7); // 13-channel hop
    }
    deauths(rig, 4);
    CHECK(rig.events().empty());
    deauths(rig, 1, 100);
    CHECK_EQ(rig.events().size(), 1U); // floor of 5
}

TEST(partial_coverage_costs_a_little_confidence) {
    Rig fixed;
    deauths(fixed, 20);
    Rig hopping;
    hop_three(hopping.detector);
    deauths(hopping, 7);
    CHECK_EQ(fixed.events().size(), 1U);
    CHECK_EQ(hopping.events().size(), 1U);
    CHECK_EQ(hopping.events().front().confidence + 5, fixed.events().front().confidence);
    CHECK(!fixed.events().front().coverage_percent);
}

TEST(coverage_only_applies_to_its_channel) {
    Rig rig;
    rig.detector.set_channel_coverage(1, 33);
    deauths(rig, 10, 0, 6); // channel 6 still at 100 %
    CHECK(rig.events().empty());
}

TEST(min_threshold_above_threshold_is_rejected) {
    DeauthBurstConfig config;
    config.threshold = 4;
    config.min_threshold = 5;
    CHECK(DeauthBurstRule(config).config_rejected());
    config.min_threshold = 0;
    CHECK(DeauthBurstRule(config).config_rejected());
}
