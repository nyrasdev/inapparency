// Throws garbage and damaged frames at the parser. These tests only pass
// meaningfully under the sanitizer build, which turns any out-of-bounds read
// into a hard failure.

#include <cstdint>
#include <vector>

#include "check.hpp"
#include "frame_builder.hpp"
#include "inapparency/parser.hpp"

using namespace inapparency;
using testing::FrameBuilder;
using testing::observe;

namespace {

// Small deterministic PRNG so failures are reproducible.
struct XorShift {
    std::uint32_t state;
    std::uint32_t next() {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    }
    std::uint8_t byte() { return static_cast<std::uint8_t>(next() & 0xFF); }
};

std::vector<std::uint8_t> rich_beacon() {
    return FrameBuilder(ManagementSubtype::Beacon)
        .beacon_fixed()
        .ssid("robustness")
        .element(1, {0x82, 0x84})
        .element(3, {11})
        .element(48, {0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
                      0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x08, 0xc0, 0x00})
        .build();
}

void parse_copy(const std::vector<std::uint8_t>& bytes, bool fcs) {
    // Exact-size heap copy so ASan sees any read past the end.
    std::vector<std::uint8_t> exact(bytes.begin(), bytes.end());
    exact.shrink_to_fit();
    auto obs = observe(exact);
    obs.includes_fcs = fcs;
    auto r = parse_frame(obs);
    CHECK(r.frame.body.size() <= exact.size());
}

} // namespace

TEST(every_prefix_of_a_valid_beacon) {
    auto full = rich_beacon();
    for (std::size_t len = 0; len <= full.size(); ++len) {
        std::vector<std::uint8_t> prefix(full.begin(),
                                         full.begin() + static_cast<std::ptrdiff_t>(len));
        parse_copy(prefix, false);
        parse_copy(prefix, true);
    }
}

TEST(every_single_byte_mutation_of_a_valid_beacon) {
    auto full = rich_beacon();
    for (std::size_t i = 0; i < full.size(); ++i) {
        for (std::uint8_t v : {std::uint8_t{0x00}, std::uint8_t{0x01}, std::uint8_t{0x7f},
                               std::uint8_t{0x80}, std::uint8_t{0xff}}) {
            auto mutated = full;
            mutated[i] = v;
            parse_copy(mutated, false);
        }
    }
}

TEST(random_buffers) {
    XorShift rng{0x1234abcd};
    for (int i = 0; i < 20000; ++i) {
        std::vector<std::uint8_t> buf(rng.next() % 300);
        for (auto& b : buf) {
            b = rng.byte();
        }
        // Bias half the cases toward management frames so the deeper paths
        // actually get exercised.
        if (!buf.empty() && (i % 2) == 0) {
            buf[0] = static_cast<std::uint8_t>(buf[0] & 0xF0);
            if (buf.size() > 1) {
                buf[1] = static_cast<std::uint8_t>(buf[1] & 0xBF); // clear protected
            }
        }
        parse_copy(buf, (i % 3) == 0);
    }
}

TEST(random_element_soup_after_valid_header) {
    XorShift rng{0xfeedbeef};
    auto header = FrameBuilder(ManagementSubtype::Beacon).beacon_fixed().build();
    for (int i = 0; i < 20000; ++i) {
        auto buf = header;
        std::size_t extra = rng.next() % 200;
        for (std::size_t j = 0; j < extra; ++j) {
            buf.push_back(rng.byte());
        }
        parse_copy(buf, false);
    }
}
