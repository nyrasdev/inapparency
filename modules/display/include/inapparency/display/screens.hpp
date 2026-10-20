#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "inapparency/display/framebuffer.hpp"
#include "inapparency/event.hpp"

namespace inapparency::display {

// The project logo, drawn with the custom φ and ・ glyphs.
inline constexpr const char* kLogo = "φ(・・;";

struct LastAlert {
    Severity severity = Severity::Info;
    const char* rule = "";
    std::uint8_t confidence = 0;
    std::optional<MacAddress> bssid;
    std::uint64_t at_ms = 0;
};

// Everything the status screen shows. Plain values, so it can be copied
// between tasks under a short lock.
struct StatusView {
    std::uint64_t uptime_ms = 0;
    std::uint64_t frames = 0;
    std::uint64_t alerts = 0;
    std::uint64_t suppressed = 0;
    std::uint32_t dropped = 0;
    std::optional<std::uint8_t> channel;
    bool hopping = false;
    bool storage_enabled = false;
    bool storage_ok = false;
    std::optional<LastAlert> last_alert;
};

// How long a high or critical alert stays highlighted.
inline constexpr std::uint64_t kHighlightMs = 10'000;

void render_splash(Framebuffer& fb, const char* version);
void render_status(Framebuffer& fb, const StatusView& view);

// Short forms that fit on a 21-character line.
// 987 -> "987", 12345 -> "12.3k", 4500000 -> "4.5M".
std::array<char, 16> format_count(std::uint64_t n);
// 61 s -> "1m01s", 3720 s -> "1h02m", 2 days -> "2d00h".
std::array<char, 16> format_uptime(std::uint64_t ms);
// "02:ee:ee:ee:ee:01" fits exactly; this is just MacAddress::to_string.

} // namespace inapparency::display
