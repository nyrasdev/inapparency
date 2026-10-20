#pragma once

#include <array>
#include <cstdint>

#include "inapparency/mac_table.hpp"
#include "inapparency/rolling_counter.hpp"
#include "inapparency/rule.hpp"

namespace inapparency::rules {

struct AuthFloodConfig {
    std::uint32_t window_ms = 5000;
    // Authentication + (re)association requests to one AP inside the window.
    std::uint32_t threshold = 50;
    // Different client addresses needed. One client retrying a lot is a
    // bad connection, not a flood.
    std::uint32_t min_sources = 10;
    std::uint32_t cooldown_ms = 30'000;
    // Floor when the threshold is scaled down for channel coverage.
    std::uint32_t min_threshold = 15;

    bool valid() const;
};

// Flags a flood of join attempts against one access point from many
// addresses: the classic way to fill an AP's client table so real devices
// can't connect.
class AuthFloodRule final : public Rule {
public:
    static constexpr std::uint32_t kId = 5;
    static constexpr std::size_t kTrackedNetworks = 8;
    static constexpr std::size_t kTrackedSources = 24;

    explicit AuthFloodRule(const AuthFloodConfig& config = {});

    const RuleInfo& info() const override;
    void evaluate(const Observation& observation, const ParseResult& result,
                  const DetectionContext& context, EventSink& sink) override;

    const AuthFloodConfig& config() const { return config_; }
    bool config_rejected() const { return config_rejected_; }

private:
    static constexpr std::size_t kBuckets = 20;

    struct State {
        RollingCounter<kBuckets> requests;
        RollingCounter<kBuckets> randomized; // locally administered sources
        std::array<MacAddress, kTrackedSources> sources{};
        std::array<std::uint64_t, kTrackedSources> source_seen_ms{};
        std::array<bool, kTrackedSources> source_used{};
        std::uint64_t quiet_until_ms = 0;
        bool has_fired = false;
    };

    // Returns how many distinct sources were seen inside the window, capped
    // at kTrackedSources.
    std::uint32_t note_source(State& state, const MacAddress& source, std::uint64_t now_ms) const;

    AuthFloodConfig config_;
    bool config_rejected_ = false;
    MacTable<State, kTrackedNetworks> networks_;
};

} // namespace inapparency::rules
