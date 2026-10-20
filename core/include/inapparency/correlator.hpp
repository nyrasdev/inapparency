#pragma once

#include <array>
#include <cstdint>

#include "inapparency/rule.hpp"

namespace inapparency {

struct CorrelatorConfig {
    // How far apart the two halves of an attack can be.
    std::uint32_t window_ms = 120'000;
    std::uint32_t cooldown_ms = 300'000;

    bool valid() const;
};

// Looks at the events rules produce and spots combinations that mean more
// together than apart. Passes every event through unchanged, and adds an
// `attack-chain` event when it finds one.
//
// The pattern it knows: an impostor access point (evil-twin, or ap-change
// alternating on the same BSSID) plus a deauth burst against the real one.
// Kicking clients off the real network so they reconnect to a fake one is
// how most evil twin attacks actually work. Order doesn't matter.
//
// Goes between the detector and the event gate.
class Correlator final : public EventSink {
public:
    static constexpr std::uint32_t kChainRuleId = 100;
    static constexpr std::size_t kRemembered = 8;

    explicit Correlator(EventSink& out, const CorrelatorConfig& config = {});

    void emit(const DetectionEvent& event) override;

    std::uint64_t chains() const { return chains_; }
    bool config_rejected() const { return config_rejected_; }

private:
    enum class Kind : std::uint8_t { Disruption, Impostor };

    struct Seen {
        bool used = false;
        Kind kind = Kind::Disruption;
        MacAddress target; // the real access point
        std::optional<MacAddress> impostor;
        std::uint8_t confidence = 0;
        std::uint64_t at_ms = 0;
    };

    struct Fired {
        bool used = false;
        MacAddress target;
        std::uint64_t until_ms = 0;
    };

    void remember(Kind kind, const MacAddress& target, const DetectionEvent& event);

    EventSink& out_;
    CorrelatorConfig config_;
    bool config_rejected_ = false;
    std::array<Seen, kRemembered> seen_{};
    std::array<Fired, kRemembered> fired_{};
    std::uint64_t chains_ = 0;
};

} // namespace inapparency
