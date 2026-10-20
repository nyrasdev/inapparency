#include "inapparency/display/framebuffer.hpp"

#include "inapparency/display/font.hpp"

namespace inapparency::display {

void Framebuffer::set(int x, int y, bool on) {
    if (x < 0 || y < 0 || x >= kWidth || y >= kHeight) {
        return;
    }
    std::uint8_t& b = bytes_[static_cast<std::size_t>((y / 8) * kWidth + x)];
    const auto mask = static_cast<std::uint8_t>(1U << (y % 8));
    b = on ? static_cast<std::uint8_t>(b | mask) : static_cast<std::uint8_t>(b & ~mask);
}

bool Framebuffer::get(int x, int y) const {
    if (x < 0 || y < 0 || x >= kWidth || y >= kHeight) {
        return false;
    }
    return (bytes_[static_cast<std::size_t>((y / 8) * kWidth + x)] & (1U << (y % 8))) != 0;
}

void Framebuffer::fill_rect(int x, int y, int w, int h, bool on) {
    for (int yy = y; yy < y + h; ++yy) {
        for (int xx = x; xx < x + w; ++xx) {
            set(xx, yy, on);
        }
    }
}

void Framebuffer::invert_rect(int x, int y, int w, int h) {
    for (int yy = y; yy < y + h; ++yy) {
        for (int xx = x; xx < x + w; ++xx) {
            if (xx >= 0 && yy >= 0 && xx < kWidth && yy < kHeight) {
                set(xx, yy, !get(xx, yy));
            }
        }
    }
}

int Framebuffer::draw_text(int x, int y, std::string_view utf8, int scale, bool on) {
    if (scale < 1) {
        scale = 1;
    }
    int cursor = x;
    std::size_t pos = 0;
    while (pos < utf8.size()) {
        const Glyph& g = glyph_for(next_code_point(utf8, pos));
        for (int col = 0; col < 5; ++col) {
            for (int row = 0; row < 7; ++row) {
                if (((g[static_cast<std::size_t>(col)] >> row) & 1) != 0) {
                    fill_rect(cursor + col * scale, y + row * scale, scale, scale, on);
                }
            }
        }
        cursor += kCharWidth * scale;
    }
    return cursor - x;
}

int Framebuffer::text_width(std::string_view utf8, int scale) {
    if (scale < 1) {
        scale = 1;
    }
    int chars = 0;
    std::size_t pos = 0;
    while (pos < utf8.size()) {
        next_code_point(utf8, pos);
        ++chars;
    }
    return chars * kCharWidth * scale;
}

std::size_t Framebuffer::lit_pixels(int x, int y, int w, int h) const {
    std::size_t n = 0;
    for (int yy = y; yy < y + h; ++yy) {
        for (int xx = x; xx < x + w; ++xx) {
            n += get(xx, yy) ? 1U : 0U;
        }
    }
    return n;
}

} // namespace inapparency::display
