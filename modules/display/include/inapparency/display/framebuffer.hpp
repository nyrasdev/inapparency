#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace inapparency::display {

// 128x64 monochrome screen in the layout SSD1306/SH1106 controllers use:
// 8 "pages" of 8 pixel rows, one byte per column per page, bit 0 on top.
// That means a flush is a straight copy, no conversion.
class Framebuffer {
public:
    static constexpr int kWidth = 128;
    static constexpr int kHeight = 64;
    static constexpr std::size_t kBytes = kWidth * kHeight / 8;

    void clear() { bytes_.fill(0); }

    // Out-of-range coordinates are ignored, so drawing can run off the edge.
    void set(int x, int y, bool on = true);
    bool get(int x, int y) const;

    void fill_rect(int x, int y, int w, int h, bool on = true);
    void invert_rect(int x, int y, int w, int h);
    void hline(int x, int y, int w, bool on = true) { fill_rect(x, y, w, 1, on); }

    // Draws UTF-8 text with the built-in 5x7 font (6 px per character with
    // spacing), each pixel scaled up `scale` times. Returns the width drawn.
    // Unknown characters show as '?'.
    int draw_text(int x, int y, std::string_view utf8, int scale = 1, bool on = true);

    static int text_width(std::string_view utf8, int scale = 1);
    static constexpr int kCharWidth = 6;
    static constexpr int kCharHeight = 8;

    std::span<const std::uint8_t> page(int index) const {
        return {bytes_.data() + static_cast<std::size_t>(index) * kWidth,
                static_cast<std::size_t>(kWidth)};
    }
    std::span<const std::uint8_t> bytes() const { return bytes_; }

    std::size_t lit_pixels(int x, int y, int w, int h) const;

private:
    std::array<std::uint8_t, kBytes> bytes_{};
};

} // namespace inapparency::display
