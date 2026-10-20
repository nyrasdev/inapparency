#pragma once

#include <array>
#include <cstdint>
#include <optional>

#include "inapparency/frame.hpp"
#include "inapparency/mac_table.hpp"
#include "inapparency/observation.hpp"
#include "inapparency/parser.hpp"

namespace inapparency {

// What we've learned about one access point from its beacons and probe
// responses.
struct NetworkRecord {
    std::optional<Ssid> ssid;
    std::optional<std::uint8_t> channel;
    std::optional<RsnInfo> rsn; // from the latest beacon

    // Sticky: once a BSSID has advertised PMF, a later beacon without it
    // doesn't erase that. Beacons can be forged, and a forged "no PMF"
    // beacon shouldn't be able to make forged deauths look normal.
    bool pmf_required_seen = false;
    bool pmf_capable_seen = false;

    std::uint32_t beacons_seen = 0;
    std::uint64_t first_seen_ms = 0;
    std::uint64_t last_seen_ms = 0;
};

// Shared knowledge that every rule can read but only the detector writes.
class DetectionContext {
public:
    static constexpr std::size_t kNetworkCapacity = 32;

    const NetworkRecord* network(const MacAddress& bssid) const { return networks_.find(bssid); }
    std::size_t network_count() const { return networks_.size(); }
    std::uint32_t networks_evicted() const { return networks_.evictions(); }

    void learn(const Observation& observation, const ParseResult& result);

    // Share of time (0-100 %) the radio listens on a channel. While hopping
    // across three channels each gets about 33 %, so a rule sees about a
    // third of what happens there. Unknown or unset channels count as 100.
    std::uint8_t coverage(std::optional<std::uint8_t> channel) const {
        if (!channel || *channel >= coverage_.size()) {
            return 100;
        }
        return coverage_[*channel];
    }
    // Values outside 1-100 are ignored.
    void set_coverage(std::uint8_t channel, std::uint8_t percent) {
        if (channel < coverage_.size() && percent >= 1 && percent <= 100) {
            coverage_[channel] = percent;
        }
    }

private:
    MacTable<NetworkRecord, kNetworkCapacity> networks_;
    std::array<std::uint8_t, 15> coverage_ = [] {
        std::array<std::uint8_t, 15> a{};
        a.fill(100);
        return a;
    }();
};

} // namespace inapparency
