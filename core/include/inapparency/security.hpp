#pragma once

#include <cstdint>
#include <optional>

#include "inapparency/frame.hpp"

namespace inapparency {

// How strongly a network advertises itself as protected, from what a beacon
// or probe response says. Higher rank is stronger.
struct SecurityProfile {
    enum Rank : std::uint8_t {
        Open = 0,
        Legacy = 1,      // privacy bit but no RSN: WEP or WPA1
        Wpa2 = 2,        // RSN without PMF
        PmfOptional = 3, // RSN, PMF supported
        PmfRequired = 4, // RSN, PMF required (all WPA3)
    };

    Rank rank = Open;
    std::uint32_t akm_suites = 0;

    bool offers_sae() const {
        return (akm_suites & ((std::uint32_t{1} << akm::sae) | (std::uint32_t{1} << 24))) != 0;
    }

    // True when this profile gives clients less protection than `other`.
    bool weaker_than(const SecurityProfile& other) const {
        if (rank != other.rank) {
            return rank < other.rank;
        }
        return other.offers_sae() && !offers_sae();
    }

    friend bool operator==(const SecurityProfile&, const SecurityProfile&) = default;
};

const char* to_string(SecurityProfile::Rank rank);

// Needs the capability field, so only works for beacons, probe responses
// and association frames.
std::optional<SecurityProfile> security_profile(const ManagementInfo& info);

} // namespace inapparency
