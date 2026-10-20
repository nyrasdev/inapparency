#pragma once

#include <cstdint>
#include <optional>

#include "inapparency/mac_table.hpp"
#include "inapparency/rolling_counter.hpp"
#include "inapparency/rule.hpp"
#include "inapparency/security.hpp"

namespace inapparency::rules {

struct ApChangeConfig {
    // Matching beacons needed before a BSSID's normal look is trusted.
    std::uint32_t confirmations = 3;
    // Differing beacons inside the window needed to report.
    std::uint32_t threshold = 3;
    std::uint32_t window_ms = 10'000;
    std::uint32_t cooldown_ms = 60'000;
    // If the old setup hasn't come back after this long, call it replaced.
    std::uint32_t settle_ms = 2'000;

    bool valid() const;
};

// What a beacon says about its access point.
struct BeaconFingerprint {
    std::optional<Ssid> ssid; // empty for hidden networks
    std::optional<std::uint8_t> channel;
    std::uint16_t beacon_interval = 0;
    SecurityProfile security;

    friend bool operator==(const BeaconFingerprint&, const BeaconFingerprint&) = default;
};

// Learns how each access point normally looks and reports when its beacons
// change: a different name, channel, timing or (worst) weaker security.
//
// Two cases get told apart:
// - the old and new look keep alternating: something else is beaconing with
//   the same BSSID, a strong sign of a spoofed access point
// - the new look replaced the old one: usually a reconfiguration, unless
//   security got weaker
//
// A BSSID is only judged after its first few beacons agree, so an impostor
// that's already on the air when monitoring starts can prevent a baseline
// from forming. evil-twin covers the more common different-BSSID case.
class ApChangeRule final : public Rule {
public:
    static constexpr std::uint32_t kId = 3;
    static constexpr std::size_t kTrackedNetworks = 32;

    explicit ApChangeRule(const ApChangeConfig& config = {});

    const RuleInfo& info() const override;
    void evaluate(const Observation& observation, const ParseResult& result,
                  const DetectionContext& context, EventSink& sink) override;

    const ApChangeConfig& config() const { return config_; }
    bool config_rejected() const { return config_rejected_; }

private:
    struct State {
        BeaconFingerprint baseline;
        std::uint32_t confirmations = 0;
        bool established = false;
        RollingCounter<10> mismatches;
        std::uint64_t baseline_seen_ms = 0;
        std::uint64_t first_mismatch_ms = 0;
        std::uint64_t quiet_until_ms = 0;
        bool has_fired = false;
    };

    ApChangeConfig config_;
    bool config_rejected_ = false;
    MacTable<State, kTrackedNetworks> networks_;
};

} // namespace inapparency::rules
