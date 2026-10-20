#include "inapparency/display/screens.hpp"

#include <cinttypes>
#include <cstdio>

namespace inapparency::display {
namespace {

constexpr int kW = Framebuffer::kWidth;

void centered(Framebuffer& fb, int y, const char* text, int scale = 1) {
    int w = Framebuffer::text_width(text, scale);
    fb.draw_text((kW - w) / 2, y, text, scale);
}

void right(Framebuffer& fb, int y, const char* text) {
    // text_width counts 1 px of spacing after the last glyph, so this
    // leaves exactly 1 px of margin on the right.
    fb.draw_text(kW - Framebuffer::text_width(text), y, text);
}

// Text label, e.g. "HIGH".
const char* severity_label(Severity s) {
    switch (s) {
    case Severity::Info:
        return "INFO";
    case Severity::Low:
        return "LOW";
    case Severity::Medium:
        return "MED";
    case Severity::High:
        return "HIGH";
    case Severity::Critical:
        return "CRIT";
    }
    return "?";
}

} // namespace

std::array<char, 16> format_count(std::uint64_t n) {
    std::array<char, 16> out{};
    if (n < 10'000) {
        std::snprintf(out.data(), out.size(), "%" PRIu64, n);
    } else if (n < 1'000'000) {
        std::snprintf(out.data(), out.size(), "%" PRIu64 ".%" PRIu64 "k", n / 1000,
                      (n % 1000) / 100);
    } else if (n < 1'000'000'000) {
        std::snprintf(out.data(), out.size(), "%" PRIu64 ".%" PRIu64 "M", n / 1'000'000,
                      (n % 1'000'000) / 100'000);
    } else {
        std::snprintf(out.data(), out.size(), "%" PRIu64 "G", n / 1'000'000'000);
    }
    return out;
}

std::array<char, 16> format_uptime(std::uint64_t ms) {
    std::array<char, 16> out{};
    std::uint64_t s = ms / 1000;
    if (s < 3600) {
        std::snprintf(out.data(), out.size(), "%um%02us", static_cast<unsigned>(s / 60),
                      static_cast<unsigned>(s % 60));
    } else if (s < 86'400) {
        std::snprintf(out.data(), out.size(), "%uh%02um", static_cast<unsigned>(s / 3600),
                      static_cast<unsigned>((s % 3600) / 60));
    } else {
        std::uint64_t days = s / 86'400;
        if (days > 999) {
            days = 999;
        }
        std::snprintf(out.data(), out.size(), "%ud%02uh", static_cast<unsigned>(days),
                      static_cast<unsigned>((s % 86'400) / 3600));
    }
    return out;
}

void render_splash_logo(Framebuffer& fb) {
    fb.clear();
    const Bitmap& logo = kLogoBitmap;
    const int x0 = (kW - logo.width) / 2;
    const int y0 = (Framebuffer::kHeight - logo.height) / 2;
    for (int y = 0; y < logo.height; ++y) {
        for (int x = 0; x < logo.width; ++x) {
            if (logo.get(x, y)) {
                fb.set(x0 + x, y0 + y);
            }
        }
    }
}

void render_splash_name(Framebuffer& fb, const char* version) {
    fb.clear();
    centered(fb, 18, "inapparency", 1);
    char line[24];
    std::snprintf(line, sizeof line, "v%s", version);
    centered(fb, 32, line);
    centered(fb, 46, "passive monitor");
}

void render_status(Framebuffer& fb, const StatusView& v) {
    fb.clear();
    char line[24];

    // Header: name, storage marker on the right.
    fb.draw_text(0, 0, "inapparency");
    if (v.storage_enabled) {
        right(fb, 0, "SD");
        if (!v.storage_ok) {
            fb.invert_rect(kW - 14, 0, 14, 8); // inverted = card missing or failing
        }
    }
    fb.hline(0, 9, kW);

    if (v.channel) {
        std::snprintf(line, sizeof line, "ch %u %s", static_cast<unsigned>(*v.channel),
                      v.hopping ? "hop" : "fixed");
    } else {
        std::snprintf(line, sizeof line, "ch -");
    }
    fb.draw_text(0, 12, line);
    std::snprintf(line, sizeof line, "up %s", format_uptime(v.uptime_ms).data());
    right(fb, 12, line);

    std::snprintf(line, sizeof line, "frames %s", format_count(v.frames).data());
    fb.draw_text(0, 22, line);
    std::snprintf(line, sizeof line, "drop %s", format_count(v.dropped).data());
    right(fb, 22, line);

    std::snprintf(line, sizeof line, "alerts %s", format_count(v.alerts).data());
    fb.draw_text(0, 32, line);
    std::snprintf(line, sizeof line, "held %s", format_count(v.suppressed).data());
    right(fb, 32, line);

    fb.hline(0, 42, kW);

    if (!v.last_alert) {
        centered(fb, 50, "no alerts yet");
        return;
    }
    const LastAlert& a = *v.last_alert;
    std::snprintf(line, sizeof line, "%s %s", severity_label(a.severity), a.rule);
    fb.draw_text(1, 45, line);
    std::snprintf(line, sizeof line, "%u%%", static_cast<unsigned>(a.confidence));
    right(fb, 45, line);
    if (a.bssid) {
        fb.draw_text(1, 55, a.bssid->to_string().data());
    } else {
        std::uint64_t ago = v.uptime_ms > a.at_ms ? v.uptime_ms - a.at_ms : 0;
        std::snprintf(line, sizeof line, "%s ago", format_uptime(ago).data());
        fb.draw_text(1, 55, line);
    }

    // A fresh high or critical alert gets the whole box inverted so it can
    // be seen from across the room.
    const bool fresh = v.uptime_ms >= a.at_ms && v.uptime_ms - a.at_ms < kHighlightMs;
    if (fresh && a.severity >= Severity::High) {
        fb.invert_rect(0, 43, kW, 21);
    }
}

} // namespace inapparency::display
