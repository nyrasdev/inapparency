#include <cstring>

#include "check.hpp"
#include "inapparency/rules/ap_change.hpp"
#include "inapparency/security.hpp"
#include "scenario.hpp"

using namespace inapparency;
using namespace testing;
using rules::ApChangeConfig;
using rules::ApChangeRule;

namespace {

struct Rig {
    ApChangeRule rule;
    Detector detector;
    Scenario scenario{detector};

    explicit Rig(const ApChangeConfig& config = {}) : rule(config) { detector.add_rule(rule); }
    const std::vector<DetectionEvent>& events() const { return scenario.sink.events; }
};

SecurityProfile profile_of(Security s) {
    auto r = parse_frame(observe(beacon(kAccessPoint, s)));
    auto p = security_profile(r.frame.management);
    CHECK(p.has_value());
    return p.value_or(SecurityProfile{});
}

bool mentions(const DetectionEvent& e, const char* text) {
    return std::strstr(e.explanation, text) != nullptr;
}

// 2 s of normal beacons from the real AP so the baseline forms.
void settle_in(Rig& rig, Security security = Security::Wpa3PmfRequired) {
    for (std::uint64_t t = 0; t < 2000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, security, 6, "home"), t);
    }
}

} // namespace

TEST(security_ranks) {
    CHECK(profile_of(Security::Open).rank == SecurityProfile::Open);
    CHECK(profile_of(Security::Wpa2NoPmf).rank == SecurityProfile::Wpa2);
    CHECK(profile_of(Security::Wpa2PmfOptional).rank == SecurityProfile::PmfOptional);
    CHECK(profile_of(Security::Wpa3PmfRequired).rank == SecurityProfile::PmfRequired);
    CHECK(profile_of(Security::Wpa3PmfRequired).offers_sae());
    CHECK(!profile_of(Security::Wpa2NoPmf).offers_sae());
}

TEST(security_legacy_privacy_bit) {
    // Privacy bit set, no RSN element: WEP or WPA1.
    auto bytes =
        FrameBuilder(ManagementSubtype::Beacon).beacon_fixed(100, 0x0411).ssid("old").build();
    auto p = security_profile(parse_frame(observe(bytes)).frame.management);
    CHECK(p && p->rank == SecurityProfile::Legacy);
}

TEST(security_weaker_than) {
    auto open = profile_of(Security::Open);
    auto wpa2 = profile_of(Security::Wpa2NoPmf);
    auto wpa3 = profile_of(Security::Wpa3PmfRequired);
    CHECK(open.weaker_than(wpa2));
    CHECK(wpa2.weaker_than(wpa3));
    CHECK(!wpa3.weaker_than(wpa2));
    CHECK(!wpa2.weaker_than(wpa2));

    // Same rank but SAE dropped (WPA3 -> WPA2 with PMF forced on) is weaker.
    SecurityProfile sae_dropped = wpa3;
    sae_dropped.akm_suites = std::uint32_t{1} << akm::psk;
    CHECK(sae_dropped.weaker_than(wpa3));
}

TEST(security_needs_capability_field) {
    auto deauth_frame = deauth(kAccessPoint, kClient);
    CHECK(!security_profile(parse_frame(observe(deauth_frame)).frame.management));
}

TEST(ap_steady_network_is_quiet) {
    Rig rig;
    for (std::uint64_t t = 0; t < 120'000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 6, "home"), t);
    }
    CHECK(rig.events().empty());
}

TEST(ap_spoofed_downgrade_alternating_is_high) {
    Rig rig;
    settle_in(rig);
    // Impostor with the same BSSID, open, beaconing between the real ones.
    for (std::uint64_t t = 2000; t < 3000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 6, "home"), t);
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Open, 6, "home"), t + 50);
    }
    CHECK_EQ(rig.events().size(), 1U);
    const auto& e = rig.events().front();
    CHECK(e.severity == Severity::High);
    CHECK_EQ(e.confidence, 80);
    CHECK(e.bssid == kAccessPoint);
    CHECK(mentions(e, "impersonating"));
}

TEST(ap_spoofed_same_security_different_channel) {
    Rig rig;
    settle_in(rig);
    for (std::uint64_t t = 2000; t < 3000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 6, "home"), t);
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 11, "home"), t + 50);
    }
    CHECK_EQ(rig.events().size(), 1U);
    CHECK(rig.events().front().severity == Severity::Medium);
    CHECK(mentions(rig.events().front(), "two different setups"));
}

TEST(ap_reconfiguration_is_info_once) {
    Rig rig;
    settle_in(rig, Security::Wpa2NoPmf);
    // Owner moves the AP to channel 1 and renames it. Old setup never returns.
    for (std::uint64_t t = 2000; t < 60'000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa2NoPmf, 1, "home-2"), t);
    }
    CHECK_EQ(rig.events().size(), 1U);
    const auto& e = rig.events().front();
    CHECK(e.severity == Severity::Info);
    CHECK(e.timestamp_ms >= 4000); // waited to see if the old setup returns
    CHECK(mentions(e, "normal reconfiguration"));
}

TEST(ap_security_upgrade_is_not_a_downgrade) {
    Rig rig;
    settle_in(rig, Security::Wpa2NoPmf);
    for (std::uint64_t t = 2000; t < 30'000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 6, "home"), t);
    }
    CHECK_EQ(rig.events().size(), 1U);
    CHECK(rig.events().front().severity == Severity::Info);
}

TEST(ap_replaced_with_weaker_security_is_high) {
    Rig rig;
    settle_in(rig);
    for (std::uint64_t t = 2000; t < 30'000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa2NoPmf, 6, "home"), t);
    }
    CHECK_EQ(rig.events().size(), 1U);
    CHECK(rig.events().front().severity == Severity::High);
    CHECK_EQ(rig.events().front().confidence, 55);
}

TEST(ap_one_odd_beacon_is_ignored) {
    Rig rig;
    settle_in(rig);
    rig.scenario.feed(beacon_with(kAccessPoint, Security::Open, 6, "home"), 2050);
    rig.scenario.feed(beacon_with(kAccessPoint, Security::Open, 6, "home"), 2150);
    for (std::uint64_t t = 2100; t < 30'000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 6, "home"), t);
    }
    CHECK(rig.events().empty());
}

TEST(ap_hidden_ssid_doesnt_count_as_a_change) {
    Rig rig;
    for (std::uint64_t t = 0; t < 30'000; t += 100) {
        // Hidden networks alternate between empty and zeroed SSIDs on some APs.
        auto empty = beacon_with(kAccessPoint, Security::Wpa2NoPmf, 6, "");
        auto zeros =
            beacon_with(kAccessPoint, Security::Wpa2NoPmf, 6, std::string_view("\0\0\0\0", 4));
        rig.scenario.feed((t / 100) % 2 == 0 ? empty : zeros, t);
    }
    CHECK(rig.events().empty());
}

TEST(ap_cooldown_limits_repeats) {
    Rig rig;
    settle_in(rig);
    for (std::uint64_t t = 2000; t < 130'000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 6, "home"), t);
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Open, 6, "home"), t + 50);
    }
    CHECK_EQ(rig.events().size(), 3U); // ~2 s, ~62 s, ~122 s
}

TEST(ap_invalid_config) {
    ApChangeConfig c;
    c.settle_ms = c.window_ms;
    CHECK(ApChangeRule(c).config_rejected());
    c = ApChangeConfig{};
    c.confirmations = 0;
    CHECK(ApChangeRule(c).config_rejected());
    CHECK(!ApChangeRule().config_rejected());
}
