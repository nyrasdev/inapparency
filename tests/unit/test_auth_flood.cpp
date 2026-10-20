#include "check.hpp"
#include "inapparency/rules/auth_flood.hpp"
#include "scenario.hpp"

using namespace inapparency;
using namespace testing;
using rules::AuthFloodConfig;
using rules::AuthFloodRule;

namespace {

struct Rig {
    AuthFloodRule rule;
    Detector detector;
    Scenario scenario{detector};

    explicit Rig(const AuthFloodConfig& config = {}) : rule(config) { detector.add_rule(rule); }
    const std::vector<DetectionEvent>& events() const { return scenario.sink.events; }
};

MacAddress client(std::uint32_t i, bool randomized = true) {
    return mac(randomized ? 0x02 : 0x00, 0x77, 0x00, static_cast<std::uint8_t>(i >> 16),
               static_cast<std::uint8_t>(i >> 8), static_cast<std::uint8_t>(i));
}

// `n` auth requests from `sources` different clients, 10 ms apart.
void flood(Rig& rig, int n, std::uint32_t sources, std::uint64_t start = 0,
           bool randomized = true) {
    for (int i = 0; i < n; ++i) {
        auto c = client(static_cast<std::uint32_t>(i) % sources, randomized);
        rig.scenario.feed(i % 2 == 0 ? auth_request(kAccessPoint, c)
                                     : assoc_request(kAccessPoint, c),
                          start + static_cast<std::uint64_t>(i) * 10);
    }
}

} // namespace

TEST(auth_flood_from_many_random_sources) {
    Rig rig;
    flood(rig, 200, 1000);
    CHECK_EQ(rig.events().size(), 1U);
    const auto& e = rig.events().front();
    CHECK(e.severity == Severity::Medium);
    CHECK(e.bssid == kAccessPoint);
    CHECK_EQ(e.evidence_count, 50U);
    CHECK_EQ(e.confidence, 55); // 40 + 10 table full + 5 randomized
}

TEST(auth_one_client_retrying_is_not_a_flood) {
    Rig rig;
    flood(rig, 300, 1);
    CHECK(rig.events().empty());
}

TEST(auth_a_few_clients_retrying_is_not_a_flood) {
    Rig rig;
    flood(rig, 300, 5);
    CHECK(rig.events().empty());
}

TEST(auth_normal_joins_are_quiet) {
    Rig rig;
    // 30 devices joining over a minute (a class walking in).
    for (std::uint32_t i = 0; i < 30; ++i) {
        std::uint64_t t = i * 2000;
        rig.scenario.feed(auth_request(kAccessPoint, client(i)), t);
        rig.scenario.feed(assoc_request(kAccessPoint, client(i)), t + 5);
    }
    CHECK(rig.events().empty());
}

TEST(auth_responses_from_the_ap_dont_count) {
    Rig rig;
    for (int i = 0; i < 200; ++i) {
        auto response = FrameBuilder(ManagementSubtype::Authentication)
                            .receiver(client(static_cast<std::uint32_t>(i)))
                            .transmitter(kAccessPoint)
                            .bssid(kAccessPoint)
                            .le16(0)
                            .le16(2) // AP's reply
                            .le16(0)
                            .build();
        rig.scenario.feed(response, static_cast<std::uint64_t>(i) * 10);
    }
    CHECK(rig.events().empty());
}

TEST(auth_universal_macs_get_no_random_bonus) {
    Rig rig;
    flood(rig, 200, 1000, 0, false);
    CHECK_EQ(rig.events().size(), 1U);
    CHECK_EQ(rig.events().front().confidence, 50);
}

TEST(auth_hopping_scales_threshold) {
    Rig fixed;
    flood(fixed, 20, 1000);
    CHECK(fixed.events().empty());

    Rig hopping;
    for (std::uint8_t ch : {std::uint8_t{1}, std::uint8_t{6}, std::uint8_t{11}}) {
        hopping.detector.set_channel_coverage(ch, 33);
    }
    flood(hopping, 20, 1000);
    CHECK_EQ(hopping.events().size(), 1U);
    CHECK(hopping.events().front().coverage_percent == std::uint8_t{33});
}

TEST(auth_cooldown) {
    Rig rig;
    for (std::uint64_t t = 0; t < 70'000; t += 20) {
        rig.scenario.feed(auth_request(kAccessPoint, client(static_cast<std::uint32_t>(t))), t);
    }
    CHECK_EQ(rig.events().size(), 3U);
}

TEST(auth_invalid_config) {
    AuthFloodConfig c;
    c.min_sources = 100; // more than can be tracked
    CHECK(AuthFloodRule(c).config_rejected());
    c = AuthFloodConfig{};
    c.min_threshold = c.threshold + 1;
    CHECK(AuthFloodRule(c).config_rejected());
    CHECK(!AuthFloodRule().config_rejected());
}
