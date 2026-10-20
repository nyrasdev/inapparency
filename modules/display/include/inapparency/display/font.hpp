#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace inapparency::display {

// One 5x7 glyph: five columns, bit 0 is the top row.
using Glyph = std::array<std::uint8_t, 5>;

// Glyph for a Unicode code point. Covers printable ASCII plus the two extra
// characters the logo needs: φ (U+03C6) and ・ (U+30FB, also U+00B7).
// Anything else gets '?'.
const Glyph& glyph_for(char32_t code_point);
bool has_glyph(char32_t code_point);

// Reads one UTF-8 character starting at `text[pos]` and moves `pos` past
// it. Broken sequences decode as U+FFFD and consume one byte.
char32_t next_code_point(std::string_view text, std::size_t& pos);

} // namespace inapparency::display
