#include <cstring>
#include <string>

#include "check.hpp"
#include "inapparency/display/font.hpp"
#include "inapparency/display/screens.hpp"

using namespace inapparency;
using namespace inapparency::display;

namespace {

// Renders a region as rows of '#' and '.' for exact comparisons.
std::string ascii(const Framebuffer& fb, int x, int y, int w, int h) {
    std::string out;
    for (int yy = y; yy < y + h; ++yy) {
        for (int xx = x; xx < x + w; ++xx) {
            out += fb.get(xx, yy) ? '#' : '.';
        }
        out += '\n';
    }
    return out;
}

StatusView sample_view() {
    StatusView v;
    v.uptime_ms = 60'000;
    v.frames = 1234;
    v.channel = 6;
    v.hopping = true;
    return v;
}

} // namespace

TEST(fb_set_get_and_bounds) {
    Framebuffer fb;
    fb.set(0, 0);
    fb.set(127, 63);
    fb.set(-1, 5);  // ignored
    fb.set(128, 0); // ignored
    fb.set(5, 64);  // ignored
    CHECK(fb.get(0, 0) && fb.get(127, 63));
    CHECK(!fb.get(-1, 5) && !fb.get(1, 0));
    CHECK_EQ(fb.lit_pixels(0, 0, 128, 64), 2U);
}

TEST(fb_page_layout_matches_controller) {
    // SSD1306: page p holds rows 8p..8p+7, bit 0 = top row.
    Framebuffer fb;
    fb.set(3, 0);
    fb.set(3, 7);
    fb.set(3, 8);
    CHECK_EQ(fb.page(0)[3], 0x81);
    CHECK_EQ(fb.page(1)[3], 0x01);
    CHECK_EQ(fb.bytes().size(), 1024U);
}

TEST(fb_invert_and_clear) {
    Framebuffer fb;
    fb.fill_rect(0, 0, 4, 4);
    fb.invert_rect(2, 2, 4, 4);
    CHECK(!fb.get(3, 3) && fb.get(4, 4) && fb.get(0, 0));
    fb.clear();
    CHECK_EQ(fb.lit_pixels(0, 0, 128, 64), 0U);
}

TEST(font_covers_printable_ascii) {
    for (char32_t c = 0x21; c <= 0x7E; ++c) {
        CHECK(has_glyph(c));
        const auto& g = glyph_for(c);
        bool any = false;
        for (auto col : g) {
            any = any || col != 0;
            CHECK((col & 0x80) == 0); // 7 rows only
        }
        CHECK(any);
    }
    CHECK(!has_glyph(U'é'));
    CHECK(glyph_for(U'é') == glyph_for(U'?'));
}

TEST(utf8_decoding) {
    std::string_view s = "aφ・\U0001F600";
    std::size_t pos = 0;
    CHECK(next_code_point(s, pos) == U'a');
    CHECK(next_code_point(s, pos) == U'φ');
    CHECK(next_code_point(s, pos) == U'・');
    CHECK(next_code_point(s, pos) == U'\U0001F600');
    CHECK_EQ(pos, s.size());

    std::string bad = "\xe3\x83"; // cut-off 3-byte sequence
    pos = 0;
    CHECK(next_code_point(bad, pos) == 0xFFFD);
    CHECK_EQ(pos, 1U);
    CHECK(next_code_point(bad, pos) == 0xFFFD);
    CHECK_EQ(pos, 2U);
}

TEST(text_width_counts_characters_not_bytes) {
    CHECK_EQ(Framebuffer::text_width("\u03c6(\u30fb\u30fb;"), 30); // 5 characters
    CHECK_EQ(Framebuffer::text_width("\u03c6(\u30fb\u30fb;", 3), 90);
    CHECK_EQ(Framebuffer::text_width("abc"), 18);
}

TEST(extra_glyphs_look_right) {
    Framebuffer fb;
    fb.draw_text(0, 0, "\u03c6(\u30fb\u30fb;");
    // φ ( ・ ・ ; at 6 px per character, pixel for pixel.
    // clang-format off
    CHECK(ascii(fb, 0, 0, 30, 7) ==
          "..#......#....................\n"
          ".###....#................##...\n"
          "#.#.#..#......#.....#....##...\n"
          "#.#.#..#.....###...###........\n"
          ".###...#......#.....#....##...\n"
          "..#.....#.................#...\n"
          "..#......#...............#....\n");
    // clang-format on
    // φ: vertical stroke through the middle, ring around it.
    for (int y = 0; y < 7; ++y) {
        CHECK(fb.get(2, y));
    }
    CHECK(fb.get(0, 2) && fb.get(0, 3) && fb.get(4, 2) && fb.get(4, 3));
    // Each ・ is a small diamond centered on row 3.
    for (int base : {12, 18}) {
        CHECK(fb.get(base + 2, 2) && fb.get(base + 1, 3) && fb.get(base + 2, 3) &&
              fb.get(base + 3, 3) && fb.get(base + 2, 4));
        CHECK_EQ(fb.lit_pixels(base, 0, 6, 7), 5U);
    }
}

TEST(splash_logo_is_centered_and_exact) {
    Framebuffer fb;
    render_splash_logo(fb);
    const Bitmap& logo = kLogoBitmap;
    CHECK(logo.width <= Framebuffer::kWidth && logo.height <= Framebuffer::kHeight);
    const int x0 = (Framebuffer::kWidth - logo.width) / 2;
    const int y0 = (Framebuffer::kHeight - logo.height) / 2;
    std::size_t lit = 0;
    bool exact = true;
    for (int y = 0; y < logo.height; ++y) {
        for (int x = 0; x < logo.width; ++x) {
            exact = exact && fb.get(x0 + x, y0 + y) == logo.get(x, y);
            lit += logo.get(x, y) ? 1U : 0U;
        }
    }
    CHECK(exact);
    CHECK(lit > 200);                            // not blank
    CHECK_EQ(fb.lit_pixels(0, 0, 128, 64), lit); // nothing outside it
}

TEST(splash_name_shows_text) {
    Framebuffer fb;
    render_splash_name(fb, "0.1.0");
    CHECK(fb.lit_pixels(0, 18, 128, 7) > 30); // name
    CHECK(fb.lit_pixels(0, 32, 128, 7) > 10); // version
    CHECK(fb.lit_pixels(0, 46, 128, 7) > 30); // "passive monitor"
}

TEST(bitmap_bounds) {
    const std::uint8_t data[] = {0x80, 0x01};
    Bitmap b{8, 2, data};
    CHECK(b.get(0, 0) && !b.get(1, 0) && b.get(7, 1));
    CHECK(!b.get(-1, 0) && !b.get(8, 0) && !b.get(0, 2));
}

TEST(status_without_alert) {
    Framebuffer fb;
    render_status(fb, sample_view());
    CHECK(fb.lit_pixels(0, 9, 128, 1) == 128);  // header rule
    CHECK(fb.lit_pixels(0, 42, 128, 1) == 128); // alert box rule
    CHECK(fb.lit_pixels(0, 50, 128, 7) > 20);   // "no alerts yet"
    CHECK_EQ(fb.lit_pixels(100, 0, 28, 8), 0U); // no SD marker
}

TEST(status_sd_marker) {
    Framebuffer ok_fb;
    Framebuffer bad_fb;
    StatusView v = sample_view();
    v.storage_enabled = true;
    v.storage_ok = true;
    render_status(ok_fb, v);
    v.storage_ok = false;
    render_status(bad_fb, v);
    CHECK(ok_fb.lit_pixels(114, 0, 14, 8) > 0);
    // Inverted when the card has a problem: mostly lit.
    CHECK(bad_fb.lit_pixels(114, 0, 14, 8) > ok_fb.lit_pixels(114, 0, 14, 8));
}

TEST(status_fresh_high_alert_is_inverted_then_not) {
    StatusView v = sample_view();
    LastAlert a;
    a.severity = Severity::Critical;
    a.rule = "attack-chain";
    a.confidence = 95;
    a.bssid = MacAddress{{0x02, 0xee, 0xee, 0xee, 0xee, 0x01}};
    a.at_ms = 58'000;
    v.last_alert = a;

    Framebuffer fresh;
    render_status(fresh, v);
    CHECK(fresh.lit_pixels(0, 43, 128, 21) > 128 * 21 / 2);

    v.uptime_ms = 58'000 + kHighlightMs;
    Framebuffer old;
    render_status(old, v);
    CHECK(old.lit_pixels(0, 43, 128, 21) < 128 * 21 / 2);
    CHECK(old.lit_pixels(0, 43, 128, 21) > 50);
}

TEST(status_low_alert_is_never_inverted) {
    StatusView v = sample_view();
    LastAlert a;
    a.severity = Severity::Low;
    a.rule = "malformed-frames";
    a.at_ms = 59'000;
    v.last_alert = a;
    Framebuffer fb;
    render_status(fb, v);
    CHECK(fb.lit_pixels(0, 43, 128, 21) < 128 * 21 / 2);
}

TEST(format_helpers) {
    CHECK(std::strcmp(format_count(0).data(), "0") == 0);
    CHECK(std::strcmp(format_count(9999).data(), "9999") == 0);
    CHECK(std::strcmp(format_count(12'345).data(), "12.3k") == 0);
    CHECK(std::strcmp(format_count(4'560'000).data(), "4.5M") == 0);
    CHECK(std::strcmp(format_count(7'000'000'000ULL).data(), "7G") == 0);

    CHECK(std::strcmp(format_uptime(61'000).data(), "1m01s") == 0);
    CHECK(std::strcmp(format_uptime(3'720'000).data(), "1h02m") == 0);
    CHECK(std::strcmp(format_uptime(2ULL * 86'400'000).data(), "2d00h") == 0);
    CHECK(std::strcmp(format_uptime(5000ULL * 86'400'000).data(), "999d00h") == 0);
}

TEST(status_long_values_stay_on_screen) {
    StatusView v = sample_view();
    v.frames = 999'999'999'999ULL;
    v.alerts = 999'999'999'999ULL;
    v.uptime_ms = 999ULL * 86'400'000;
    LastAlert a;
    a.rule = "a-very-long-rule-name-that-overflows";
    v.last_alert = a;
    Framebuffer fb;
    render_status(fb, v); // must not crash or wrap; drawing clips at the edge
    CHECK(fb.lit_pixels(0, 0, 128, 64) > 0);
}
