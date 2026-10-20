#include <cstring>
#include <string>
#include <vector>

#include "check.hpp"
#include "frame_builder.hpp"
#include "inapparency/host/pcap.hpp"
#include "inapparency/parser.hpp"

using namespace inapparency;
using namespace inapparency::host;

namespace {

void put32(std::vector<std::uint8_t>& v, std::uint32_t x, bool big = false) {
    for (int i = 0; i < 4; ++i) {
        int shift = big ? (3 - i) * 8 : i * 8;
        v.push_back(static_cast<std::uint8_t>(x >> shift));
    }
}

void put16(std::vector<std::uint8_t>& v, std::uint16_t x, bool big = false) {
    if (big) {
        v.push_back(static_cast<std::uint8_t>(x >> 8));
        v.push_back(static_cast<std::uint8_t>(x));
    } else {
        v.push_back(static_cast<std::uint8_t>(x));
        v.push_back(static_cast<std::uint8_t>(x >> 8));
    }
}

std::vector<std::uint8_t> pcap_header(std::uint32_t linktype, bool big = false,
                                      std::uint32_t magic = 0xa1b2c3d4) {
    std::vector<std::uint8_t> v;
    put32(v, magic, big);
    put16(v, 2, big);
    put16(v, 4, big);
    put32(v, 0, big);
    put32(v, 0, big);
    put32(v, 65535, big);
    put32(v, linktype, big);
    return v;
}

void add_record(std::vector<std::uint8_t>& file, std::uint32_t sec, std::uint32_t frac,
                const std::vector<std::uint8_t>& data, bool big = false) {
    put32(file, sec, big);
    put32(file, frac, big);
    put32(file, static_cast<std::uint32_t>(data.size()), big);
    put32(file, static_cast<std::uint32_t>(data.size()), big);
    file.insert(file.end(), data.begin(), data.end());
}

// Radiotap with flags, channel and signal (and optionally TSFT first).
std::vector<std::uint8_t> radiotap(std::uint16_t mhz, std::int8_t dbm, std::uint8_t flags = 0,
                                   bool with_tsft = false) {
    std::vector<std::uint8_t> h{0, 0, 0, 0};
    std::uint32_t present = (1U << 1) | (1U << 3) | (1U << 5) | (with_tsft ? 1U : 0U);
    put32(h, present);
    if (with_tsft) {
        for (int i = 0; i < 8; ++i) {
            h.push_back(0xee); // offset 8 is already 8-aligned
        }
    }
    h.push_back(flags);
    h.push_back(0); // align channel to 2
    put16(h, mhz);
    put16(h, 0x00a0);
    h.push_back(static_cast<std::uint8_t>(dbm));
    h[2] = static_cast<std::uint8_t>(h.size());
    return h;
}

std::vector<std::uint8_t> deauth_frame() {
    return testing::FrameBuilder(ManagementSubtype::Deauthentication).le16(7).build();
}

std::vector<std::uint8_t> concat(std::vector<std::uint8_t> a, const std::vector<std::uint8_t>& b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

} // namespace

TEST(pcap_channel_mapping) {
    CHECK(channel_from_frequency(2412) == std::uint8_t{1});
    CHECK(channel_from_frequency(2437) == std::uint8_t{6});
    CHECK(channel_from_frequency(2472) == std::uint8_t{13});
    CHECK(channel_from_frequency(2484) == std::uint8_t{14});
    CHECK(channel_from_frequency(5180) == std::uint8_t{36});
    CHECK(!channel_from_frequency(2413));
    CHECK(!channel_from_frequency(900));
}

TEST(radiotap_basic_fields) {
    auto h = radiotap(2437, -52, 0x10);
    auto info = parse_radiotap(h);
    CHECK(info.has_value());
    CHECK(info && info->header_length == h.size());
    CHECK(info && info->frequency_mhz == std::uint16_t{2437});
    CHECK(info && info->signal_dbm == std::int8_t{-52});
    CHECK(info && info->fcs_at_end && !info->bad_fcs);
}

TEST(radiotap_with_tsft_keeps_alignment) {
    auto info = parse_radiotap(radiotap(2412, -70, 0, true));
    CHECK(info && info->frequency_mhz == std::uint16_t{2412});
    CHECK(info && info->signal_dbm == std::int8_t{-70});
}

TEST(radiotap_extended_bitmap) {
    // present word with bit 31, then a second word, then fields.
    std::vector<std::uint8_t> h{0, 0, 0, 0};
    put32(h, (1U << 31) | (1U << 5));
    put32(h, 0);
    h.push_back(static_cast<std::uint8_t>(-60));
    h[2] = static_cast<std::uint8_t>(h.size());
    auto info = parse_radiotap(h);
    CHECK(info && info->signal_dbm == std::int8_t{-60});
}

TEST(radiotap_rejects_broken_headers) {
    CHECK(!parse_radiotap(std::vector<std::uint8_t>{0, 0, 4}));
    auto bad_version = radiotap(2412, -50);
    bad_version[0] = 1;
    CHECK(!parse_radiotap(bad_version));
    auto too_long = radiotap(2412, -50);
    too_long[2] = 200;
    CHECK(!parse_radiotap(too_long));
    auto fields_missing = radiotap(2412, -50);
    fields_missing[2] = 10; // claims channel but header ends first
    CHECK(!parse_radiotap(fields_missing));
}

TEST(pcap_reads_radiotap_capture) {
    auto file = pcap_header(kLinktypeRadiotap);
    add_record(file, 100, 250'000, concat(radiotap(2462, -45), deauth_frame()));
    add_record(file, 100, 500'000, concat(radiotap(2462, -45, 0x40), deauth_frame())); // bad FCS

    std::string error;
    auto reader = PcapReader::open(file, error);
    CHECK(reader.has_value());
    if (!reader) {
        return;
    }
    CHECK_EQ(reader->linktype(), kLinktypeRadiotap);

    auto p = reader->next();
    CHECK(p.has_value());
    auto obs = to_observation(*p, reader->linktype());
    CHECK(obs.has_value());
    CHECK_EQ(obs->timestamp_ms, 100'250U);
    CHECK(obs->channel == std::uint8_t{11});
    CHECK(obs->rssi_dbm == std::int8_t{-45});
    CHECK(obs->original_length == std::size_t{deauth_frame().size()});
    CHECK(parse_frame(*obs).frame.management.reason_code == std::uint16_t{7});

    p = reader->next();
    CHECK(p.has_value() && !to_observation(*p, reader->linktype())); // skipped
    CHECK(!reader->next());
    CHECK(!reader->truncated());
}

TEST(pcap_big_endian_nanoseconds_raw_80211) {
    auto file = pcap_header(kLinktypeIeee80211, true, 0xa1b23c4d);
    auto frame = concat(deauth_frame(), {0xde, 0xad, 0xbe, 0xef});
    add_record(file, 2, 3'000'000, frame, true);

    std::string error;
    auto reader = PcapReader::open(file, error);
    CHECK(reader.has_value());
    if (!reader) {
        return;
    }
    auto p = reader->next();
    CHECK(p && p->timestamp_us == 2'003'000U);
    auto obs = to_observation(*p, reader->linktype(), true);
    CHECK(obs && obs->includes_fcs);
    CHECK(parse_frame(*obs).ok());
    CHECK_EQ(parse_frame(*obs).frame.body.size(), 2U);
}

TEST(pcap_truncated_record) {
    auto file = pcap_header(kLinktypeIeee80211);
    add_record(file, 1, 0, deauth_frame());
    file.resize(file.size() - 5);
    std::string error;
    auto reader = PcapReader::open(file, error);
    CHECK(reader && !reader->next());
    CHECK(reader && reader->truncated());
}

TEST(pcap_rejects_other_files) {
    std::string error;
    CHECK(!PcapReader::open({1, 2, 3}, error));

    auto ethernet = pcap_header(1);
    CHECK(!PcapReader::open(ethernet, error));
    CHECK(error.find("link type 1") != std::string::npos);

    std::vector<std::uint8_t> pcapng(32, 0);
    pcapng[0] = 0x0a;
    pcapng[1] = 0x0d;
    pcapng[2] = 0x0d;
    pcapng[3] = 0x0a;
    CHECK(!PcapReader::open(pcapng, error));
    CHECK(error.find("pcapng") != std::string::npos);

    std::vector<std::uint8_t> junk(64, 0x55);
    CHECK(!PcapReader::open(junk, error));
}

TEST(pcap_random_garbage_never_crashes) {
    std::uint32_t state = 99;
    auto rnd = [&state] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    };
    for (int i = 0; i < 2000; ++i) {
        auto file = pcap_header(kLinktypeRadiotap);
        std::size_t extra = rnd() % 400;
        for (std::size_t j = 0; j < extra; ++j) {
            file.push_back(static_cast<std::uint8_t>(rnd()));
        }
        std::string error;
        auto reader = PcapReader::open(file, error);
        while (reader) {
            auto p = reader->next();
            if (!p) {
                break;
            }
            if (auto obs = to_observation(*p, reader->linktype())) {
                parse_frame(*obs);
            }
        }
    }
    CHECK(true);
}
