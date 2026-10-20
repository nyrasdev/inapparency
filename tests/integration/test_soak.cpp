// Ten simulated minutes of hostile, messy traffic through the full pipeline
// (detector + rules + event gate). Checks that nothing grows, nothing gets
// lost without being counted, and output stays inside its budget.

#include <chrono>

#include "check.hpp"
#include "inapparency/correlator.hpp"
#include "inapparency/default_rules.hpp"
#include "inapparency/event_gate.hpp"
#include "scenario.hpp"

using namespace inapparency;
using namespace testing;

namespace {

struct XorShift {
    std::uint32_t state;
    std::uint32_t next() {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    }
    std::uint8_t byte() { return static_cast<std::uint8_t>(next()); }
};

MacAddress random_ap(XorShift& rng, std::uint32_t pool) {
    std::uint32_t i = rng.next() % pool;
    return mac(0x02, 0x50, static_cast<std::uint8_t>(i >> 16), static_cast<std::uint8_t>(i >> 8),
               static_cast<std::uint8_t>(i), 0x01);
}

} // namespace

TEST(soak_ten_minutes_of_chaos) {
    DefaultRules rule_set;
    Detector detector;
    CHECK(rule_set.attach(detector));
    for (std::uint8_t ch : {std::uint8_t{1}, std::uint8_t{6}, std::uint8_t{11}}) {
        detector.set_channel_coverage(ch, 33);
    }

    CollectingSink out;
    EventGate gate(out);
    Correlator correlator(gate);
    XorShift rng{0xC0FFEE};

    std::uint64_t frames = 0;
    auto started = std::chrono::steady_clock::now();
    const std::uint8_t channels[] = {1, 6, 11};

    for (std::uint64_t t = 0; t < 600'000; t += 5) {
        Observation obs;
        obs.timestamp_ms = t;
        obs.channel = channels[(t / 500) % 3];
        obs.rssi_dbm = static_cast<std::int8_t>(-30 - static_cast<int>(rng.next() % 60));

        std::vector<std::uint8_t> bytes;
        switch (rng.next() % 10) {
        case 0:
        case 1:
        case 2: // beacons from 500 different APs: far more than the tables hold
            bytes =
                beacon(random_ap(rng, 500), static_cast<Security>(rng.next() % 4), *obs.channel);
            break;
        case 3:
        case 4: // deauths spread over 300 spoofed BSSIDs
            bytes =
                deauth(random_ap(rng, 300), kBroadcast, static_cast<std::uint16_t>(rng.next() % 8));
            break;
        case 5: // a few hot targets that really are flooded
            bytes = deauth(random_ap(rng, 4), kBroadcast, 7);
            break;
        case 6: // garbage
            bytes.resize(rng.next() % 120);
            for (auto& b : bytes) {
                b = rng.byte();
            }
            break;
        case 9: // join attempts from random addresses
            bytes = auth_request(random_ap(rng, 4), mac(0x02, rng.byte(), rng.byte(), rng.byte(),
                                                        rng.byte(), rng.byte()));
            break;
        case 7: // truncated management frames
            bytes = deauth(kAccessPoint, kClient);
            bytes.resize(rng.next() % bytes.size());
            break;
        case 8:
            if (rng.next() % 2 == 0) { // open copies of the APs with random names
                bytes = beacon_with(random_ap(rng, 500), Security::Open, *obs.channel, "lab");
                break;
            }
            [[fallthrough]];
        default: // ordinary probe requests
            bytes = FrameBuilder(ManagementSubtype::ProbeRequest).ssid("").build();
            break;
        }
        // Every so often time jumps backwards a bit, like a resynced clock.
        if (rng.next() % 1000 == 0 && obs.timestamp_ms > 2000) {
            obs.timestamp_ms -= 2000;
        }
        obs.bytes = bytes;
        detector.process(obs, correlator);
        ++frames;
    }

    double seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    std::printf("    soak: %llu frames in %.2f s (%.0f frames/s on this machine)\n",
                static_cast<unsigned long long>(frames), seconds,
                static_cast<double>(frames) / seconds);

    const auto& stats = detector.stats();
    const auto& g = gate.stats();
    CHECK_EQ(stats.observations, frames);
    CHECK_EQ(stats.ok + stats.empty + stats.truncated + stats.bad_version + stats.unsupported,
             frames);

    // Every event (from rules, plus attack chains) is either printed or counted.
    CHECK_EQ(g.passed + g.duplicates + g.rate_limited, stats.events + correlator.chains());
    CHECK_EQ(out.events.size(), g.passed);

    // Output stays inside the budget: 5 burst + 20/min for 10 minutes, plus
    // critical chains (which skip the budget but are capped per target).
    std::uint64_t critical = 0;
    for (const auto& e : out.events) {
        critical += e.severity == Severity::Critical ? 1U : 0U;
    }
    CHECK(g.passed - critical <= 5 + 20 * 10 + 1);
    CHECK(critical <= 4 * 2 + 300); // each target at most once per 5 min
    CHECK(g.passed > 0);
    CHECK(g.rate_limited + g.duplicates > 0);

    // Tables stayed at their fixed size.
    CHECK(detector.context().network_count() <= DetectionContext::kNetworkCapacity);
    CHECK(detector.context().networks_evicted() > 0);

    for (const auto& e : out.events) {
        CHECK(e.confidence <= 95);
        CHECK(e.explanation != nullptr && e.explanation[0] != '\0');
    }
}
