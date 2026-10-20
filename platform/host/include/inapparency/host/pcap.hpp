#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "inapparency/observation.hpp"

namespace inapparency::host {

// What radiotap told us about one frame.
struct RadiotapInfo {
    std::size_t header_length = 0;
    std::optional<std::uint16_t> frequency_mhz;
    std::optional<std::int8_t> signal_dbm;
    bool fcs_at_end = false;
    bool bad_fcs = false;
};

// Parses the radiotap header in front of a frame. Returns nothing if the
// header is broken. Only the fields we use are decoded; everything else is
// skipped using its known size and alignment.
std::optional<RadiotapInfo> parse_radiotap(std::span<const std::uint8_t> packet);

// 2412 -> 1, 2484 -> 14, 5180 -> 36. Nothing for frequencies we don't map.
std::optional<std::uint8_t> channel_from_frequency(std::uint16_t mhz);

// Link types we can read.
inline constexpr std::uint32_t kLinktypeIeee80211 = 105;
inline constexpr std::uint32_t kLinktypeRadiotap = 127;

struct PcapPacket {
    std::uint64_t timestamp_us = 0;
    std::uint32_t original_length = 0;
    std::span<const std::uint8_t> data;
};

// Reads classic .pcap files (not .pcapng) in either byte order, with
// microsecond or nanosecond timestamps.
class PcapReader {
public:
    // Takes the whole file contents. Returns nothing with `error` set when
    // the file isn't a pcap we understand.
    static std::optional<PcapReader> open(std::vector<std::uint8_t> contents, std::string& error);

    std::uint32_t linktype() const { return linktype_; }

    // Next packet, or nothing at the end. A record that runs past the end of
    // the file stops reading and sets truncated().
    std::optional<PcapPacket> next();
    bool truncated() const { return truncated_; }

private:
    PcapReader() = default;

    std::uint32_t u32(std::size_t offset) const;

    std::vector<std::uint8_t> contents_;
    std::size_t offset_ = 24;
    std::uint32_t linktype_ = 0;
    bool swapped_ = false;
    bool nanoseconds_ = false;
    bool truncated_ = false;
};

// Turns one pcap packet into an observation the detector can take. The
// observation borrows packet.data. Returns nothing for packets that should
// be skipped (bad radiotap header or a frame the radio flagged as bad FCS).
// `assume_fcs` only matters for linktype 105, where the file doesn't say.
std::optional<Observation> to_observation(const PcapPacket& packet, std::uint32_t linktype,
                                          bool assume_fcs = false);

} // namespace inapparency::host
