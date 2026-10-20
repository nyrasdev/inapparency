#pragma once

#include <array>
#include <cstdint>

#include "inapparency/rule.hpp"
#include "inapparency/security.hpp"

namespace inapparency::rules {

struct EvilTwinConfig {
    // Beacons a BSSID needs before it's taken into account. Filters out
    // one-off garbage and frames from far away.
    std::uint32_t min_beacons = 3;
    // A BSSID that appears this long after the network was first seen
    // counts as a newcomer, which is more suspicious.
    std::uint32_t newcomer_after_ms = 30'000;
    // A BSSID not heard for this long is forgotten.
    std::uint32_t expire_ms = 120'000;
    std::uint32_t cooldown_ms = 300'000;

    bool valid() const;
};

// Flags a network name that's served by several BSSIDs where one of them
// offers weaker security than another: the classic evil twin, an open or
// WPA2 copy of a network that's normally protected better.
//
// Several access points sharing a name is normal (mesh, extenders, big
// offices), so matching names alone never fire. Only a security gap does,
// and only when the weaker one isn't older than the stronger one (adding a
// WPA3 node to an old WPA2 network is an upgrade, not an attack).
class EvilTwinRule final : public Rule {
public:
    static constexpr std::uint32_t kId = 4;
    static constexpr std::size_t kTrackedNetworks = 16;
    static constexpr std::size_t kBssidsPerNetwork = 6;

    explicit EvilTwinRule(const EvilTwinConfig& config = {});

    const RuleInfo& info() const override;
    void evaluate(const Observation& observation, const ParseResult& result,
                  const DetectionContext& context, EventSink& sink) override;

    const EvilTwinConfig& config() const { return config_; }
    bool config_rejected() const { return config_rejected_; }
    std::uint32_t networks_evicted() const { return evictions_; }

private:
    struct Member {
        bool used = false;
        MacAddress bssid;
        SecurityProfile security;
        std::optional<std::uint8_t> channel;
        std::uint32_t beacons = 0;
        std::uint64_t first_seen_ms = 0;
        std::uint64_t last_seen_ms = 0;
        // This member has already been reported as the weak one.
        bool reported = false;
        std::uint64_t quiet_until_ms = 0;
    };

    struct Network {
        bool used = false;
        Ssid ssid;
        std::uint64_t first_seen_ms = 0;
        std::uint64_t last_seen_ms = 0;
        std::array<Member, kBssidsPerNetwork> members{};
    };

    Network& find_network(const Ssid& ssid, std::uint64_t now_ms);
    // Nothing when the table is full and an equivalent BSSID is tracked.
    Member* find_member(Network& network, const MacAddress& bssid, const SecurityProfile& security,
                        std::uint64_t now_ms);

    EvilTwinConfig config_;
    bool config_rejected_ = false;
    std::array<Network, kTrackedNetworks> networks_{};
    std::uint32_t evictions_ = 0;
};

} // namespace inapparency::rules
