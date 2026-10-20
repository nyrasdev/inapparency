#pragma once

#include <array>
#include <cstdint>
#include <optional>

#include "inapparency/rule.hpp"

namespace inapparency {

struct EventGateConfig {
    // Same rule + same BSSID inside this window counts as a duplicate.
    std::uint32_t dedup_ms = 10'000;
    // Output budget: long-run rate and how many can go out back to back.
    std::uint32_t max_per_minute = 20;
    std::uint32_t burst = 5;

    bool valid() const;
};

struct EventGateStats {
    std::uint64_t passed = 0;
    std::uint64_t duplicates = 0;
    std::uint64_t rate_limited = 0;

    std::uint64_t suppressed() const { return duplicates + rate_limited; }
};

// Sits between the detector and the real output. Stops the same alert from
// repeating and keeps a flood of alerts (say, from thousands of spoofed
// BSSIDs) from drowning the serial line.
//
// Nothing disappears silently: everything held back is counted, and the
// status line reports it. Critical events are deduplicated but never rate
// limited.
class EventGate final : public EventSink {
public:
    static constexpr std::size_t kRecent = 16;

    // An invalid config falls back to the defaults; check config_rejected().
    explicit EventGate(EventSink& out, const EventGateConfig& config = {});

    void emit(const DetectionEvent& event) override;

    const EventGateStats& stats() const { return stats_; }
    const EventGateConfig& config() const { return config_; }
    bool config_rejected() const { return config_rejected_; }

private:
    struct Recent {
        bool used = false;
        std::uint32_t rule_id = 0;
        std::optional<MacAddress> bssid;
        std::uint64_t at_ms = 0;
    };

    bool is_duplicate(const DetectionEvent& event);
    bool take_token(std::uint64_t now_ms);

    EventSink& out_;
    EventGateConfig config_;
    bool config_rejected_ = false;
    std::array<Recent, kRecent> recent_{};

    // Tokens are kept in thousandths so slow refill rates don't round to 0.
    std::uint64_t tokens_milli_ = 0;
    std::uint64_t last_refill_ms_ = 0;
    std::uint64_t refill_remainder_ = 0;
    bool started_ = false;

    EventGateStats stats_;
};

} // namespace inapparency
