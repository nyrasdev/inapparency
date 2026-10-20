#pragma once

#include <array>
#include <cstdint>

#include "inapparency/mac_table.hpp"
#include "inapparency/rolling_counter.hpp"
#include "inapparency/rule.hpp"

namespace inapparency::rules {

struct DeauthBurstConfig {
    std::uint32_t window_ms = 5000;
    // Deauth + disassoc frames for one BSSID inside the window.
    std::uint32_t threshold = 20;
    // After firing for a BSSID, stay quiet about it this long.
    std::uint32_t cooldown_ms = 30000;
    // While hopping, the threshold shrinks with channel coverage, but never
    // below this.
    std::uint32_t min_threshold = 5;

    bool valid() const;
};

// Flags a lot of deauthentication / disassociation frames tied to one
// network in a short time.
//
// Confidence goes up when the frames hit broadcast or many clients, all use
// the same reason code, or (most of all) when the network requires PMF but
// the frames aren't protected. A real access point with PMF on would protect
// them, so unprotected ones are very likely forged.
//
// When the channel is only watched part of the time, the threshold is scaled
// down to match (a third of the time on channel, a third of the frames), and
// confidence drops a little because less was actually seen.
class DeauthBurstRule final : public Rule {
public:
    static constexpr std::uint32_t kId = 1;
    static constexpr std::size_t kTrackedNetworks = 16;
    static constexpr std::size_t kTrackedTargets = 8;

    // An invalid config falls back to the defaults; check config_rejected().
    explicit DeauthBurstRule(const DeauthBurstConfig& config = {});

    const RuleInfo& info() const override;
    void evaluate(const Observation& observation, const ParseResult& result,
                  const DetectionContext& context, EventSink& sink) override;

    const DeauthBurstConfig& config() const { return config_; }
    bool config_rejected() const { return config_rejected_; }

private:
    static constexpr std::size_t kBuckets = 20;

    struct BurstState {
        RollingCounter<kBuckets> all;
        RollingCounter<kBuckets> unprotected;
        RollingCounter<kBuckets> broadcast;
        std::array<MacAddress, kTrackedTargets> targets{};
        std::array<std::uint64_t, kTrackedTargets> target_seen_ms{};
        std::array<bool, kTrackedTargets> target_used{};
        std::uint16_t last_reason = 0;
        std::uint32_t same_reason_streak = 0;
        MacAddress last_transmitter;
        std::uint64_t quiet_until_ms = 0;
        bool has_fired = false;
    };

    void note_target(BurstState& state, const MacAddress& target, std::uint64_t now_ms);
    std::uint32_t distinct_targets(const BurstState& state, std::uint64_t now_ms) const;

    DeauthBurstConfig config_;
    bool config_rejected_ = false;
    MacTable<BurstState, kTrackedNetworks> networks_;
};

} // namespace inapparency::rules
