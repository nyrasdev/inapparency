#include <cstring>
#include <string>

#include "check.hpp"
#include "inapparency/rules/evil_twin.hpp"
#include "scenario.hpp"

using namespace inapparency;
using namespace testing;
using rules::EvilTwinConfig;
using rules::EvilTwinRule;

namespace {

const MacAddress kTwin = mac(0x02, 0xee, 0xee, 0xee, 0xee, 0x01);
const MacAddress kMeshNode = mac(0x02, 0x11, 0x22, 0x33, 0x44, 0x66);

struct Rig {
    EvilTwinRule rule;
    Detector detector;
    Scenario scenario{detector};

    explicit Rig(const EvilTwinConfig& config = {}) : rule(config) { detector.add_rule(rule); }
    const std::vector<DetectionEvent>& events() const { return scenario.sink.events; }
};

bool mentions(const DetectionEvent& e, const char* text) {
    return std::strstr(e.explanation, text) != nullptr;
}

// Real AP beacons from 0 to `until`; twin beacons from `twin_from`.
void run(Rig& rig, Security real, Security twin, std::uint64_t twin_from, std::uint64_t until,
         std::uint8_t twin_channel = 6) {
    for (std::uint64_t t = 0; t < until; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, real, 6, "home"), t);
        if (t >= twin_from) {
            rig.scenario.feed(beacon_with(kTwin, twin, twin_channel, "home"), t + 50);
        }
    }
}

} // namespace

TEST(twin_open_copy_of_wpa3_newcomer) {
    Rig rig;
    run(rig, Security::Wpa3PmfRequired, Security::Open, 60'000, 70'000);
    CHECK_EQ(rig.events().size(), 1U);
    const auto& e = rig.events().front();
    CHECK(e.severity == Severity::High);
    CHECK(e.bssid == kTwin);
    CHECK(e.related_bssid == kAccessPoint);
    CHECK_EQ(e.confidence, 85); // 65 newcomer + 15 open + 5 PMF gap
    CHECK(mentions(e, "Classic evil twin"));
    CHECK(e.timestamp_ms < 60'500); // caught within a few beacons
}

TEST(twin_on_another_channel_adds_confidence) {
    Rig rig;
    run(rig, Security::Wpa3PmfRequired, Security::Open, 60'000, 70'000, 11);
    CHECK_EQ(rig.events().size(), 1U);
    CHECK_EQ(rig.events().front().confidence, 90);
}

TEST(twin_wpa2_copy_of_wpa3) {
    Rig rig;
    run(rig, Security::Wpa3PmfRequired, Security::Wpa2NoPmf, 60'000, 70'000);
    CHECK_EQ(rig.events().size(), 1U);
    CHECK_EQ(rig.events().front().confidence, 70);
    CHECK(mentions(rig.events().front(), "weaker security"));
}

TEST(twin_present_from_start_is_less_confident) {
    Rig rig;
    run(rig, Security::Wpa2NoPmf, Security::Open, 0, 10'000);
    CHECK_EQ(rig.events().size(), 1U);
    CHECK_EQ(rig.events().front().confidence, 50); // 35 + 15 open
    CHECK(mentions(rig.events().front(), "already on the air"));
}

TEST(twin_mesh_with_same_security_is_quiet) {
    Rig rig;
    for (std::uint64_t t = 0; t < 120'000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 6, "home"), t);
        rig.scenario.feed(beacon_with(kMeshNode, Security::Wpa3PmfRequired, 11, "home"), t + 30);
        if (t >= 60'000) {
            rig.scenario.feed(beacon_with(kTwin, Security::Wpa3PmfRequired, 1, "home"), t + 60);
        }
    }
    CHECK(rig.events().empty());
}

TEST(twin_stronger_newcomer_is_quiet) {
    // Someone adds a WPA3 node to an old WPA2 network: not a downgrade.
    Rig rig;
    run(rig, Security::Wpa2NoPmf, Security::Wpa3PmfRequired, 60'000, 70'000);
    CHECK(rig.events().empty());
}

TEST(twin_different_names_dont_mix) {
    Rig rig;
    for (std::uint64_t t = 0; t < 70'000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 6, "home"), t);
        rig.scenario.feed(beacon_with(kTwin, Security::Open, 6, "home-guest"), t + 50);
        rig.scenario.feed(beacon_with(kMeshNode, Security::Open, 6, "Home"), t + 70);
    }
    CHECK(rig.events().empty());
}

TEST(twin_needs_a_few_beacons) {
    Rig rig;
    for (std::uint64_t t = 0; t < 70'000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 6, "home"), t);
    }
    rig.scenario.feed(beacon_with(kTwin, Security::Open, 6, "home"), 70'000);
    rig.scenario.feed(beacon_with(kTwin, Security::Open, 6, "home"), 70'100);
    CHECK(rig.events().empty());
    rig.scenario.feed(beacon_with(kTwin, Security::Open, 6, "home"), 70'200);
    CHECK_EQ(rig.events().size(), 1U);
}

TEST(twin_reported_once_per_cooldown) {
    Rig rig;
    run(rig, Security::Wpa3PmfRequired, Security::Open, 60'000, 60'000 + 400'000);
    CHECK_EQ(rig.events().size(), 2U); // at ~60 s and after the 5 min cooldown
}

TEST(twin_ignores_hidden_networks) {
    Rig rig;
    for (std::uint64_t t = 0; t < 70'000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 6, ""), t);
        rig.scenario.feed(beacon_with(kTwin, Security::Open, 6, ""), t + 50);
    }
    CHECK(rig.events().empty());
}

TEST(twin_forgets_bssids_that_went_away) {
    Rig rig;
    // The protected AP is switched off at 10 s; an open one with the same
    // name shows up 5 minutes later. Nothing left to impersonate.
    for (std::uint64_t t = 0; t < 10'000; t += 100) {
        rig.scenario.feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 6, "home"), t);
    }
    for (std::uint64_t t = 310'000; t < 320'000; t += 100) {
        rig.scenario.feed(beacon_with(kTwin, Security::Open, 6, "home"), t);
    }
    CHECK(rig.events().empty());
}

TEST(twin_tables_stay_bounded) {
    Rig rig;
    for (std::uint32_t i = 0; i < 3000; ++i) {
        std::string name = "net-" + std::to_string(i);
        auto ap = mac(2, 0, 0, static_cast<std::uint8_t>(i >> 8), static_cast<std::uint8_t>(i), 1);
        rig.scenario.feed(beacon_with(ap, Security::Wpa2NoPmf, 6, name), i);
    }
    CHECK(rig.rule.networks_evicted() >= 3000 - EvilTwinRule::kTrackedNetworks);
    // Still works after all that churn.
    run(rig, Security::Wpa3PmfRequired, Security::Open, 0, 5'000);
    CHECK_EQ(rig.events().size(), 1U);
}

TEST(twin_many_bssids_one_name) {
    // More BSSIDs than slots for one name (a big venue). The weakest
    // newcomer should still be compared against a protected one.
    Rig rig;
    for (std::uint64_t t = 0; t < 70'000; t += 100) {
        for (std::uint8_t i = 0; i < 10; ++i) {
            rig.scenario.feed(beacon_with(mac(2, 9, 9, 9, 9, i), Security::Wpa2NoPmf, 6, "campus"),
                              t + i);
        }
    }
    CHECK(rig.events().empty());
    for (std::uint64_t t = 70'000; t < 71'000; t += 100) {
        for (std::uint8_t i = 0; i < 10; ++i) {
            rig.scenario.feed(beacon_with(mac(2, 9, 9, 9, 9, i), Security::Wpa2NoPmf, 6, "campus"),
                              t + i);
        }
        rig.scenario.feed(beacon_with(kTwin, Security::Open, 6, "campus"), t + 50);
    }
    CHECK_EQ(rig.events().size(), 1U);
}

TEST(twin_invalid_config) {
    EvilTwinConfig c;
    c.min_beacons = 0;
    CHECK(EvilTwinRule(c).config_rejected());
    CHECK(!EvilTwinRule().config_rejected());
}
