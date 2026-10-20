#include "check.hpp"
#include "inapparency/correlator.hpp"
#include "inapparency/rules/ap_change.hpp"
#include "inapparency/rules/deauth_burst.hpp"
#include "inapparency/rules/evil_twin.hpp"
#include "inapparency/rules/malformed_frames.hpp"
#include "scenario.hpp"

using namespace inapparency;
using namespace testing;

namespace {

const MacAddress kTwin = mac(0x02, 0xee, 0xee, 0xee, 0xee, 0x01);
const MacAddress kOtherAp = mac(0x02, 0x99, 0x99, 0x99, 0x99, 0x99);

DetectionEvent deauth_event(const MacAddress& ap, std::uint64_t at, std::uint8_t conf = 75) {
    DetectionEvent e;
    e.rule_id = rules::DeauthBurstRule::kId;
    e.timestamp_ms = at;
    e.bssid = ap;
    e.confidence = conf;
    e.severity = Severity::High;
    return e;
}

DetectionEvent twin_event(const MacAddress& twin, const MacAddress& real, std::uint64_t at,
                          std::uint8_t conf = 85) {
    DetectionEvent e;
    e.rule_id = rules::EvilTwinRule::kId;
    e.timestamp_ms = at;
    e.bssid = twin;
    e.related_bssid = real;
    e.confidence = conf;
    e.severity = Severity::High;
    return e;
}

std::size_t chains(const CollectingSink& out) {
    return out.count(Correlator::kChainRuleId);
}

} // namespace

TEST(chain_twin_then_deauth) {
    CollectingSink out;
    Correlator c(out);
    c.emit(twin_event(kTwin, kAccessPoint, 10'000));
    c.emit(deauth_event(kAccessPoint, 40'000));
    CHECK_EQ(out.events.size(), 3U); // both passed through + the chain
    CHECK_EQ(chains(out), 1U);
    const auto& chain = out.events.back();
    CHECK(chain.severity == Severity::Critical);
    CHECK(chain.bssid == kTwin);
    CHECK(chain.related_bssid == kAccessPoint);
    CHECK_EQ(chain.confidence, 95);
}

TEST(chain_deauth_then_twin) {
    CollectingSink out;
    Correlator c(out);
    c.emit(deauth_event(kAccessPoint, 10'000, 60));
    c.emit(twin_event(kTwin, kAccessPoint, 20'000, 50));
    CHECK_EQ(chains(out), 1U);
    CHECK(out.events.back().bssid == kTwin);
    CHECK_EQ(out.events.back().confidence, 70); // best half + 10
}

TEST(chain_needs_the_same_target) {
    CollectingSink out;
    Correlator c(out);
    c.emit(twin_event(kTwin, kAccessPoint, 10'000));
    c.emit(deauth_event(kOtherAp, 20'000));
    CHECK_EQ(chains(out), 0U);
}

TEST(chain_too_far_apart) {
    CollectingSink out;
    Correlator c(out);
    c.emit(twin_event(kTwin, kAccessPoint, 0));
    c.emit(deauth_event(kAccessPoint, 200'000));
    CHECK_EQ(chains(out), 0U);
}

TEST(chain_ap_change_alternating_counts_but_reconfig_doesnt) {
    CollectingSink out;
    Correlator c(out);
    DetectionEvent reconfig;
    reconfig.rule_id = rules::ApChangeRule::kId;
    reconfig.severity = Severity::Info;
    reconfig.bssid = kAccessPoint;
    reconfig.timestamp_ms = 1000;
    c.emit(reconfig);
    c.emit(deauth_event(kAccessPoint, 2000));
    CHECK_EQ(chains(out), 0U);

    DetectionEvent spoof = reconfig;
    spoof.severity = Severity::High;
    spoof.timestamp_ms = 3000;
    c.emit(spoof);
    CHECK_EQ(chains(out), 1U);
}

TEST(chain_ignores_unrelated_rules) {
    CollectingSink out;
    Correlator c(out);
    DetectionEvent malformed;
    malformed.rule_id = rules::MalformedFramesRule::kId;
    malformed.bssid = kAccessPoint;
    c.emit(malformed);
    c.emit(deauth_event(kAccessPoint, 0));
    CHECK_EQ(chains(out), 0U);
    CHECK_EQ(out.events.size(), 2U);
}

TEST(chain_cooldown_per_target) {
    CollectingSink out;
    Correlator c(out);
    c.emit(twin_event(kTwin, kAccessPoint, 0));
    for (std::uint64_t t = 30'000; t < 600'000; t += 30'000) {
        c.emit(deauth_event(kAccessPoint, t));
        c.emit(twin_event(kTwin, kAccessPoint, t + 1));
    }
    CHECK_EQ(chains(out), 2U); // at 30 s and after the 5 min cooldown

    c.emit(twin_event(kTwin, kOtherAp, 600'000));
    c.emit(deauth_event(kOtherAp, 600'001));
    CHECK_EQ(chains(out), 3U); // a different target isn't held back
}

TEST(chain_end_to_end_from_frames) {
    // Real AP (WPA3) beacons for a minute, then an open twin shows up and
    // the real AP gets flooded with forged deauths.
    rules::DeauthBurstRule deauth_rule;
    rules::EvilTwinRule twin_rule;
    Detector detector;
    detector.add_rule(deauth_rule);
    detector.add_rule(twin_rule);
    CollectingSink out;
    Correlator correlator(out);

    auto feed = [&](const std::vector<std::uint8_t>& bytes, std::uint64_t t) {
        Observation obs;
        obs.timestamp_ms = t;
        obs.bytes = bytes;
        obs.channel = 6;
        detector.process(obs, correlator);
    };
    for (std::uint64_t t = 0; t < 70'000; t += 100) {
        feed(beacon_with(kAccessPoint, Security::Wpa3PmfRequired, 6, "home"), t);
        if (t >= 60'000) {
            feed(beacon_with(kTwin, Security::Open, 6, "home"), t + 50);
        }
    }
    for (std::uint64_t i = 0; i < 100; ++i) {
        feed(deauth(kAccessPoint, kBroadcast), 70'000 + i * 10);
    }

    CHECK_EQ(out.count(rules::EvilTwinRule::kId), 1U);
    CHECK_EQ(out.count(rules::DeauthBurstRule::kId), 1U);
    CHECK_EQ(chains(out), 1U);
    CHECK_EQ(correlator.chains(), 1U);
    CHECK(out.events.back().severity == Severity::Critical);
}

TEST(chain_invalid_config) {
    CollectingSink out;
    CorrelatorConfig cfg;
    cfg.window_ms = 10;
    CHECK(Correlator(out, cfg).config_rejected());
}
