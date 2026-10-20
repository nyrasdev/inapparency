#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "inapparency/detector.hpp"
#include "inapparency/event.hpp"

namespace inapparency::serial {

enum class Format {
    Text, // easy to read on a serial monitor
    Json, // one JSON object per line, easy to pipe into other tools
};

// Everything worth printing in a periodic status line. Fields the platform
// can't provide stay empty and are left out of the output.
struct Status {
    std::uint64_t uptime_ms = 0;
    const DetectorStats* stats = nullptr;
    std::uint32_t dropped = 0;
    std::uint32_t queue_high_water = 0;
    std::optional<std::uint8_t> channel;
    std::optional<std::uint32_t> free_heap;
    std::optional<std::uint32_t> min_free_heap;
    // Events held back by the event gate (duplicates + rate limited).
    std::optional<std::uint64_t> suppressed;
    // Smallest free stack seen on the detection task, in bytes.
    std::optional<std::uint32_t> stack_free;
};

// Each function writes one line (ending in '\n') into `out`, always null
// terminated, and returns its length. A line that doesn't fit is cut short.
std::size_t format_event(const DetectionEvent& event, Format format, char* out,
                         std::size_t capacity);
std::size_t format_status(const Status& status, Format format, char* out, std::size_t capacity);

} // namespace inapparency::serial
