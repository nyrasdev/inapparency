#pragma once

// Helpers for feeding timed sequences of synthetic frames into a detector.

#include <cstdint>
#include <optional>
#include <vector>

#include "frame_builder.hpp"
#include "inapparency/detector.hpp"

namespace testing {

class CollectingSink final : public inapparency::EventSink {
public:
    void emit(const inapparency::DetectionEvent& event) override { events.push_back(event); }

    std::size_t count(std::uint32_t rule_id) const {
        std::size_t n = 0;
        for (const auto& e : events) {
            if (e.rule_id == rule_id) {
                ++n;
            }
        }
        return n;
    }

    std::vector<inapparency::DetectionEvent> events;
};

class Scenario {
public:
    explicit Scenario(inapparency::Detector& detector) : detector_(detector) {}

    void feed(const std::vector<std::uint8_t>& bytes, std::uint64_t at_ms,
              std::optional<std::uint8_t> channel = 6,
              std::optional<std::size_t> original_length = std::nullopt) {
        inapparency::Observation obs;
        obs.timestamp_ms = at_ms;
        obs.bytes = bytes;
        obs.channel = channel;
        obs.original_length = original_length;
        detector_.process(obs, sink);
    }

    CollectingSink sink;

private:
    inapparency::Detector& detector_;
};

// A beacon from `ap`, optionally with an RSN element.
enum class Security { Open, Wpa2NoPmf, Wpa2PmfOptional, Wpa3PmfRequired };

inline std::vector<std::uint8_t> beacon(const MacAddress& ap, Security security,
                                        std::uint8_t channel = 6) {
    FrameBuilder b(ManagementSubtype::Beacon);
    b.transmitter(ap).bssid(ap).beacon_fixed().ssid("lab").element(3, {channel});

    std::uint8_t akm = 2;
    std::uint16_t caps = 0;
    switch (security) {
    case Security::Open:
        return b.build();
    case Security::Wpa2NoPmf:
        break;
    case Security::Wpa2PmfOptional:
        caps = 0x0080;
        break;
    case Security::Wpa3PmfRequired:
        akm = 8;
        caps = 0x00c0;
        break;
    }
    auto lo = static_cast<std::uint8_t>(caps & 0xff);
    auto hi = static_cast<std::uint8_t>(caps >> 8);
    // clang-format off
    b.element(48, {0x01, 0x00,                          // version
                   0x00, 0x0f, 0xac, 0x04,              // group: CCMP
                   0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,  // pairwise: CCMP
                   0x01, 0x00, 0x00, 0x0f, 0xac, akm,   // AKM
                   lo, hi});                            // capabilities
    // clang-format on
    return b.build();
}

inline std::vector<std::uint8_t> deauth(const MacAddress& ap, const MacAddress& target,
                                        std::uint16_t reason = 7, bool protected_frame = false) {
    FrameBuilder b(ManagementSubtype::Deauthentication);
    b.transmitter(ap).bssid(ap).receiver(target);
    if (protected_frame) {
        b.protect().bytes({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
    } else {
        b.le16(reason);
    }
    return b.build();
}

inline std::vector<std::uint8_t> disassoc(const MacAddress& ap, const MacAddress& target,
                                          std::uint16_t reason = 8) {
    return FrameBuilder(ManagementSubtype::Disassociation)
        .transmitter(ap)
        .bssid(ap)
        .receiver(target)
        .le16(reason)
        .build();
}

} // namespace testing
