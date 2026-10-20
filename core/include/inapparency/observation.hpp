#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace inapparency {

// One frame as handed over by a platform adapter, plus whatever metadata the
// radio actually exposed. Missing metadata stays empty instead of being
// guessed.
//
// The bytes are borrowed: the caller keeps them alive while they are parsed.
struct Observation {
    std::uint64_t timestamp_ms = 0;
    std::span<const std::uint8_t> bytes;

    // Length of the frame on air, when the platform reports it. If it is
    // larger than bytes.size() the capture was cut short.
    std::optional<std::size_t> original_length;

    std::optional<std::uint8_t> channel;
    std::optional<std::int8_t> rssi_dbm;

    // True when the trailing 4-byte FCS is still attached to bytes.
    bool includes_fcs = false;
};

} // namespace inapparency
