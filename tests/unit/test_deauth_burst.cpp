#include <cstring>

#include "check.hpp"
#include "inapparency/rules/deauth_burst.hpp"
#include "scenario.hpp"

using namespace inapparency;
using namespace testing;
using rules::DeauthBurstConfig;
using rules::DeauthBurstRule;

namespace {

const MacAddress kOtherAp = mac(0x02, 0x99, 0x88, 0x77, 0x66, 0x55);

bool mentions(const DetectionEvent& e, const char* text) {
    return std::strstr(e.explanation, text) != nullptr;
}

struct Rig {
    DeauthBurstRule rule;
    Detector detector;
    Scenario scenario{detector};

    explicit Rig(const DeauthBurstConfig& config = {}) : rule(config) { detector.add_rule(rule); }
    const std::vector<DetectionEvent>& events() const { return scenario.sink.events; }
};

// 100 deauths over 2 s, starting at `start`.
void burst(Rig& rig, const MacAddress& ap, std::uint64_t start, bool protected_frames = false,
           const MacAddress& target = kBroadcast) {
    for (std::uint64_t i = 0; i < 100; ++i) {
        rig.scenario.feed(deauth(ap, target, 7, protected_frames), start + i * 20);
    }
}

std::uint8_t burst_confidence(Security security, bool protected_frames = false) {
    Rig rig;
    rig.scenario.feed(beacon(kAccessPoint, security), 0);
    burst(rig, kAccessPoint, 100, protected_frames);
    return rig.events().empty() ? 0 : rig.events().front().confidence;
}

} // namespace

TEST(deauth_normal_roaming_stays_quiet) {
    Rig rig;
    rig.scenario.feed(beacon(kAccessPoint, Security::Wpa2NoPmf), 0);
    for (std::uint64_t i = 0; i < 5; ++i) {
        rig.scenario.feed(deauth(kAccessPoint, kClient, 3), 1000 + i * 1000);
    }
    CHECK(rig.events().empty());
}

TEST(deauth_slow_trickle_never_fires) {
    Rig rig;
    for (std::uint64_t t = 0; t < 60'000; t += 300) { // ~16 per 5 s window
        rig.scenario.feed(deauth(kAccessPoint, kClient), t);
    }
    CHECK(rig.events().empty());
}

TEST(deauth_burst_fires_once_with_details) {
    Rig rig;
    rig.scenario.feed(beacon(kAccessPoint, Security::Open), 0);
    burst(rig, kAccessPoint, 100);

    CHECK_EQ(rig.events().size(), 1U);
    const auto& e = rig.events().front();
    CHECK_EQ(e.rule_id, DeauthBurstRule::kId);
    CHECK(std::strcmp(e.rule_name, "deauth-burst") == 0);
    CHECK(e.severity == Severity::High);
    CHECK(e.bssid == kAccessPoint);
    CHECK(e.source == kAccessPoint);
    CHECK(e.channel == std::uint8_t{6});
    CHECK_EQ(e.evidence_count, 20U);
    CHECK_EQ(e.window_ms, 5000U);
    CHECK(mentions(e, "without PMF"));
    CHECK(e.confidence > 0 && e.confidence <= 95);
}

TEST(deauth_fires_exactly_at_threshold) {
    Rig rig;
    for (std::uint64_t i = 0; i < 19; ++i) {
        rig.scenario.feed(deauth(kAccessPoint, kBroadcast), i * 10);
    }
    CHECK(rig.events().empty());
    rig.scenario.feed(deauth(kAccessPoint, kBroadcast), 190);
    CHECK_EQ(rig.events().size(), 1U);
}

TEST(deauth_disassoc_frames_count_too) {
    Rig rig;
    for (std::uint64_t i = 0; i < 25; ++i) {
        rig.scenario.feed(disassoc(kAccessPoint, kBroadcast), i * 10);
    }
    CHECK_EQ(rig.events().size(), 1U);
}

TEST(deauth_sustained_attack_repeats_after_cooldown) {
    Rig rig;
    for (std::uint64_t t = 0; t < 70'000; t += 100) { // 10/s for 70 s
        rig.scenario.feed(deauth(kAccessPoint, kBroadcast), t);
    }
    // Fires at ~2 s, then again after each 30 s cooldown.
    CHECK_EQ(rig.events().size(), 3U);
}

TEST(deauth_unprotected_on_pmf_network_is_most_confident) {
    std::uint8_t pmf = burst_confidence(Security::Wpa3PmfRequired);
    std::uint8_t no_pmf = burst_confidence(Security::Wpa2NoPmf);
    std::uint8_t optional = burst_confidence(Security::Wpa2PmfOptional);
    CHECK(pmf > no_pmf);
    CHECK(pmf > optional);
    CHECK(pmf <= 95);
}

TEST(deauth_protected_on_pmf_network_is_least_confident) {
    std::uint8_t protected_pmf = burst_confidence(Security::Wpa3PmfRequired, true);
    std::uint8_t no_pmf = burst_confidence(Security::Wpa2NoPmf);
    CHECK(protected_pmf > 0); // still reported
    CHECK(protected_pmf < no_pmf);

    Rig rig;
    rig.scenario.feed(beacon(kAccessPoint, Security::Wpa3PmfRequired), 0);
    burst(rig, kAccessPoint, 100, true);
    CHECK(mentions(rig.events().front(), "ordinary"));
}

TEST(deauth_mixed_protection_on_pmf_network) {
    Rig rig;
    rig.scenario.feed(beacon(kAccessPoint, Security::Wpa3PmfRequired), 0);
    for (std::uint64_t i = 0; i < 30; ++i) {
        bool protect = (i % 4) != 0; // a quarter unprotected
        rig.scenario.feed(deauth(kAccessPoint, kBroadcast, 7, protect), 100 + i * 20);
    }
    CHECK_EQ(rig.events().size(), 1U);
    CHECK(mentions(rig.events().front(), "partly unprotected"));
}

TEST(deauth_unknown_network_says_so) {
    Rig rig;
    burst(rig, kAccessPoint, 0);
    CHECK_EQ(rig.events().size(), 1U);
    CHECK(mentions(rig.events().front(), "unknown"));
}

TEST(deauth_pmf_knowledge_survives_forged_beacon) {
    Rig rig;
    rig.scenario.feed(beacon(kAccessPoint, Security::Wpa3PmfRequired), 0);
    rig.scenario.feed(beacon(kAccessPoint, Security::Open), 50); // forged downgrade
    burst(rig, kAccessPoint, 100);
    CHECK_EQ(rig.events().size(), 1U);
    CHECK(mentions(rig.events().front(), "requires PMF"));
}

TEST(deauth_spread_across_clients_raises_confidence) {
    Rig single;
    Rig spread;
    const MacAddress clients[] = {kClient, mac(2, 1, 1, 1, 1, 1), mac(2, 2, 2, 2, 2, 2),
                                  mac(2, 3, 3, 3, 3, 3)};
    for (std::uint64_t i = 0; i < 40; ++i) {
        single.scenario.feed(deauth(kAccessPoint, kClient, 7), i * 20);
        spread.scenario.feed(deauth(kAccessPoint, clients[i % 4], 7), i * 20);
    }
    CHECK_EQ(single.events().size(), 1U);
    CHECK_EQ(spread.events().size(), 1U);
    CHECK(spread.events().front().confidence > single.events().front().confidence);
}

TEST(deauth_tracks_networks_separately) {
    Rig rig;
    for (std::uint64_t i = 0; i < 30; ++i) {
        rig.scenario.feed(deauth(kAccessPoint, kBroadcast), i * 20);
        rig.scenario.feed(deauth(kOtherAp, kBroadcast), i * 20 + 5);
    }
    CHECK_EQ(rig.events().size(), 2U);
    CHECK(rig.events()[0].bssid != rig.events()[1].bssid);
}

TEST(deauth_ten_each_on_two_networks_stays_quiet) {
    Rig rig;
    for (std::uint64_t i = 0; i < 15; ++i) {
        rig.scenario.feed(deauth(kAccessPoint, kBroadcast), i * 20);
        rig.scenario.feed(deauth(kOtherAp, kBroadcast), i * 20 + 5);
    }
    CHECK(rig.events().empty());
}

TEST(deauth_custom_threshold) {
    DeauthBurstConfig config;
    config.threshold = 5;
    config.window_ms = 1000;
    Rig rig(config);
    for (std::uint64_t i = 0; i < 5; ++i) {
        rig.scenario.feed(deauth(kAccessPoint, kBroadcast), i * 100);
    }
    CHECK_EQ(rig.events().size(), 1U);
    CHECK_EQ(rig.events().front().window_ms, 1000U);
}

TEST(deauth_invalid_config_falls_back_to_defaults) {
    DeauthBurstConfig zero_threshold;
    zero_threshold.threshold = 0;
    DeauthBurstRule a(zero_threshold);
    CHECK(a.config_rejected());
    CHECK_EQ(a.config().threshold, DeauthBurstConfig{}.threshold);

    DeauthBurstConfig huge_window;
    huge_window.window_ms = 24U * 60U * 60U * 1000U;
    CHECK(DeauthBurstRule(huge_window).config_rejected());

    CHECK(!DeauthBurstRule().config_rejected());
}

TEST(deauth_missing_channel_stays_missing) {
    Rig rig;
    for (std::uint64_t i = 0; i < 25; ++i) {
        rig.scenario.feed(deauth(kAccessPoint, kBroadcast), i * 10, std::nullopt);
    }
    CHECK_EQ(rig.events().size(), 1U);
    CHECK(!rig.events().front().channel);
}

TEST(deauth_out_of_order_timestamps) {
    Rig rig;
    const std::uint64_t times[] = {500, 100, 900, 300, 700, 200, 800, 400, 600, 1000};
    for (int round = 0; round < 3; ++round) {
        for (auto t : times) {
            rig.scenario.feed(deauth(kAccessPoint, kBroadcast), t);
        }
    }
    CHECK_EQ(rig.events().size(), 1U);
}

TEST(deauth_many_networks_dont_grow_state) {
    Rig rig;
    for (std::uint32_t i = 0; i < 2000; ++i) {
        auto ap = mac(2, 0, 0, static_cast<std::uint8_t>(i >> 8), static_cast<std::uint8_t>(i), 1);
        rig.scenario.feed(deauth(ap, kBroadcast), i);
    }
    CHECK(rig.events().empty());
    // Table churn shouldn't stop it from catching a real burst afterwards.
    burst(rig, kAccessPoint, 5000);
    CHECK_EQ(rig.events().size(), 1U);
}

TEST(deauth_rule_can_be_disabled) {
    Rig rig;
    CHECK(rig.detector.set_rule_enabled(DeauthBurstRule::kId, false));
    CHECK(!rig.detector.rule_enabled(DeauthBurstRule::kId));
    burst(rig, kAccessPoint, 0);
    CHECK(rig.events().empty());

    rig.detector.set_rule_enabled(DeauthBurstRule::kId, true);
    burst(rig, kAccessPoint, 10'000);
    CHECK_EQ(rig.events().size(), 1U);
    CHECK(!rig.detector.set_rule_enabled(999, false));
}
