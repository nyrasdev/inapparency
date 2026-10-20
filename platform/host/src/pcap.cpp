#include "inapparency/host/pcap.hpp"

#include <array>
#include <utility>

namespace inapparency::host {
namespace {

std::uint16_t le16(std::span<const std::uint8_t> b, std::size_t o) {
    return static_cast<std::uint16_t>(b[o] | (b[o + 1] << 8));
}

std::uint32_t le32(std::span<const std::uint8_t> b, std::size_t o) {
    return static_cast<std::uint32_t>(b[o]) | (static_cast<std::uint32_t>(b[o + 1]) << 8) |
           (static_cast<std::uint32_t>(b[o + 2]) << 16) |
           (static_cast<std::uint32_t>(b[o + 3]) << 24);
}

// Radiotap fields 0-13: {alignment, size}. We stop at the first field past
// what we need, so only the fields before it have to be known.
struct FieldLayout {
    std::uint8_t align;
    std::uint8_t size;
};
constexpr std::array<FieldLayout, 6> kFields{{
    {8, 8}, // 0 TSFT
    {1, 1}, // 1 flags
    {1, 1}, // 2 rate
    {2, 4}, // 3 channel: frequency + flags
    {2, 2}, // 4 FHSS
    {1, 1}, // 5 antenna signal (dBm)
}};

constexpr std::uint8_t kFlagFcsAtEnd = 0x10;
constexpr std::uint8_t kFlagBadFcs = 0x40;
constexpr std::uint32_t kExtBit = 1U << 31;

constexpr std::uint32_t kMagicMicro = 0xa1b2c3d4;
constexpr std::uint32_t kMagicNano = 0xa1b23c4d;

std::uint32_t swap32(std::uint32_t v) {
    return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | (v >> 24);
}

} // namespace

std::optional<std::uint8_t> channel_from_frequency(std::uint16_t mhz) {
    if (mhz == 2484) {
        return std::uint8_t{14};
    }
    if (mhz >= 2412 && mhz <= 2472 && (mhz - 2412) % 5 == 0) {
        return static_cast<std::uint8_t>((mhz - 2407) / 5);
    }
    if (mhz >= 5000 && mhz <= 5895 && mhz % 5 == 0) {
        return static_cast<std::uint8_t>((mhz - 5000) / 5);
    }
    return std::nullopt;
}

std::optional<RadiotapInfo> parse_radiotap(std::span<const std::uint8_t> packet) {
    if (packet.size() < 8 || packet[0] != 0) {
        return std::nullopt;
    }
    RadiotapInfo info;
    info.header_length = le16(packet, 2);
    if (info.header_length < 8 || info.header_length > packet.size()) {
        return std::nullopt;
    }
    std::span<const std::uint8_t> header = packet.first(info.header_length);

    // Present bitmaps can chain. Fields for the first bitmap come right
    // after the last bitmap.
    std::uint32_t present = le32(header, 4);
    std::size_t offset = 8;
    for (std::uint32_t word = present; (word & kExtBit) != 0;) {
        if (header.size() - offset < 4) {
            return std::nullopt;
        }
        word = le32(header, offset);
        offset += 4;
    }

    for (std::size_t bit = 0; bit < kFields.size(); ++bit) {
        if ((present & (1U << bit)) == 0) {
            continue;
        }
        const FieldLayout field = kFields[bit];
        offset = (offset + field.align - 1) & ~static_cast<std::size_t>(field.align - 1);
        if (offset > header.size() || header.size() - offset < field.size) {
            return std::nullopt;
        }
        switch (bit) {
        case 1:
            info.fcs_at_end = (header[offset] & kFlagFcsAtEnd) != 0;
            info.bad_fcs = (header[offset] & kFlagBadFcs) != 0;
            break;
        case 3:
            info.frequency_mhz = le16(header, offset);
            break;
        case 5:
            info.signal_dbm = static_cast<std::int8_t>(header[offset]);
            break;
        default:
            break;
        }
        offset += field.size;
    }
    return info;
}

std::optional<PcapReader> PcapReader::open(std::vector<std::uint8_t> contents, std::string& error) {
    if (contents.size() < 24) {
        error = "file too short to be a pcap";
        return std::nullopt;
    }
    PcapReader reader;
    reader.contents_ = std::move(contents);

    std::uint32_t magic = le32(reader.contents_, 0);
    if (magic == kMagicMicro || magic == kMagicNano) {
        reader.swapped_ = false;
    } else if (swap32(magic) == kMagicMicro || swap32(magic) == kMagicNano) {
        reader.swapped_ = true;
        magic = swap32(magic);
    } else if (magic == 0x0a0d0d0a) {
        error = "this is a pcapng file; save it as classic pcap (Wireshark: File > Save As)";
        return std::nullopt;
    } else {
        error = "not a pcap file";
        return std::nullopt;
    }
    reader.nanoseconds_ = magic == kMagicNano;
    reader.linktype_ = reader.u32(20) & 0x0FFFFFFF;

    if (reader.linktype_ != kLinktypeIeee80211 && reader.linktype_ != kLinktypeRadiotap) {
        error = "unsupported link type " + std::to_string(reader.linktype_) +
                " (need 802.11 or 802.11 + radiotap, i.e. a monitor-mode capture)";
        return std::nullopt;
    }
    return reader;
}

std::uint32_t PcapReader::u32(std::size_t offset) const {
    std::uint32_t v = le32(contents_, offset);
    return swapped_ ? swap32(v) : v;
}

std::optional<PcapPacket> PcapReader::next() {
    if (truncated_ || contents_.size() - offset_ < 16) {
        if (offset_ < contents_.size()) {
            truncated_ = true;
        }
        return std::nullopt;
    }
    std::uint64_t seconds = u32(offset_);
    std::uint64_t fraction = u32(offset_ + 4);
    std::uint32_t captured = u32(offset_ + 8);
    std::uint32_t original = u32(offset_ + 12);
    offset_ += 16;
    if (contents_.size() - offset_ < captured) {
        truncated_ = true;
        return std::nullopt;
    }

    PcapPacket packet;
    packet.timestamp_us = seconds * 1'000'000U + (nanoseconds_ ? fraction / 1000U : fraction);
    packet.original_length = original;
    packet.data = std::span<const std::uint8_t>(contents_.data() + offset_, captured);
    offset_ += captured;
    return packet;
}

std::optional<Observation> to_observation(const PcapPacket& packet, std::uint32_t linktype,
                                          bool assume_fcs) {
    Observation obs;
    obs.timestamp_ms = packet.timestamp_us / 1000U;
    std::span<const std::uint8_t> frame = packet.data;
    std::size_t header = 0;

    if (linktype == kLinktypeRadiotap) {
        auto radiotap = parse_radiotap(packet.data);
        if (!radiotap || radiotap->bad_fcs) {
            return std::nullopt;
        }
        header = radiotap->header_length;
        frame = frame.subspan(header);
        obs.includes_fcs = radiotap->fcs_at_end;
        obs.rssi_dbm = radiotap->signal_dbm;
        if (radiotap->frequency_mhz) {
            obs.channel = channel_from_frequency(*radiotap->frequency_mhz);
        }
    } else {
        obs.includes_fcs = assume_fcs;
    }

    obs.bytes = frame;
    if (packet.original_length >= header) {
        obs.original_length = packet.original_length - header;
    }
    return obs;
}

} // namespace inapparency::host
