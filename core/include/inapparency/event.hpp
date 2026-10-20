#pragma once

#include <cstdint>
#include <optional>

#include "inapparency/frame.hpp"

namespace inapparency {

// How bad it would be if the suspected behavior is real.
enum class Severity : std::uint8_t {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
};

const char* to_string(Severity severity);

// What a rule reports. Severity and confidence are kept apart on purpose: a
// high severity event can still have weak evidence behind it.
struct DetectionEvent {
    std::uint32_t rule_id = 0;
    const char* rule_name = "";
    std::uint64_t timestamp_ms = 0;
    std::uint32_t window_ms = 0;

    Severity severity = Severity::Info;
    std::uint8_t confidence = 0; // 0-100

    std::uint32_t evidence_count = 0;

    std::optional<MacAddress> bssid;
    std::optional<MacAddress> source;
    // Another BSSID involved, e.g. the real AP an evil twin imitates.
    std::optional<MacAddress> related_bssid;
    std::optional<std::uint8_t> channel;
    // Set when the channel was only watched part of the time.
    std::optional<std::uint8_t> coverage_percent;

    // Static text written by the rule, explaining what tripped it. Never
    // points into frame data.
    const char* explanation = "";
};

} // namespace inapparency
