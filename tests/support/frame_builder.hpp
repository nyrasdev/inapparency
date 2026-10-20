#pragma once

// Builds synthetic 802.11 management frames for tests. Nothing here is ever
// transmitted; it only produces byte buffers for the parser.

#include <cstdint>
#include <initializer_list>
#include <string_view>
#include <vector>

#include "inapparency/frame.hpp"
#include "inapparency/observation.hpp"

namespace testing {

using inapparency::MacAddress;
using inapparency::ManagementSubtype;

inline MacAddress mac(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d,
                      std::uint8_t e, std::uint8_t f) {
    return MacAddress{{a, b, c, d, e, f}};
}

inline const MacAddress kBroadcast = mac(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
inline const MacAddress kAccessPoint = mac(0x02, 0x11, 0x22, 0x33, 0x44, 0x55);
inline const MacAddress kClient = mac(0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);

class FrameBuilder {
public:
    explicit FrameBuilder(ManagementSubtype subtype)
        : subtype_(static_cast<std::uint8_t>(subtype)) {}

    FrameBuilder& raw_subtype(std::uint8_t subtype) {
        subtype_ = subtype;
        return *this;
    }
    FrameBuilder& type(std::uint8_t type) {
        type_ = type;
        return *this;
    }
    FrameBuilder& version(std::uint8_t version) {
        version_ = version;
        return *this;
    }
    FrameBuilder& protect() {
        flags_ |= 0x40;
        return *this;
    }
    FrameBuilder& order() {
        flags_ |= 0x80;
        return *this;
    }
    FrameBuilder& receiver(const MacAddress& m) {
        addr1_ = m;
        return *this;
    }
    FrameBuilder& transmitter(const MacAddress& m) {
        addr2_ = m;
        return *this;
    }
    FrameBuilder& bssid(const MacAddress& m) {
        addr3_ = m;
        return *this;
    }
    FrameBuilder& sequence(std::uint16_t seq, std::uint8_t frag = 0) {
        seq_ = static_cast<std::uint16_t>((seq << 4) | (frag & 0xF));
        return *this;
    }

    FrameBuilder& u8(std::uint8_t v) {
        body_.push_back(v);
        return *this;
    }
    FrameBuilder& le16(std::uint16_t v) {
        body_.push_back(static_cast<std::uint8_t>(v & 0xFF));
        body_.push_back(static_cast<std::uint8_t>(v >> 8));
        return *this;
    }
    FrameBuilder& bytes(std::initializer_list<std::uint8_t> v) {
        body_.insert(body_.end(), v);
        return *this;
    }
    FrameBuilder& element(std::uint8_t id, std::initializer_list<std::uint8_t> data) {
        body_.push_back(id);
        body_.push_back(static_cast<std::uint8_t>(data.size()));
        body_.insert(body_.end(), data);
        return *this;
    }
    FrameBuilder& ssid(std::string_view name) {
        body_.push_back(0);
        body_.push_back(static_cast<std::uint8_t>(name.size()));
        for (char c : name) {
            body_.push_back(static_cast<std::uint8_t>(c));
        }
        return *this;
    }
    // Timestamp, beacon interval, capability info.
    FrameBuilder& beacon_fixed(std::uint16_t interval = 100, std::uint16_t capability = 0x0411) {
        for (int i = 0; i < 8; ++i) {
            body_.push_back(0);
        }
        le16(interval);
        le16(capability);
        return *this;
    }

    std::vector<std::uint8_t> build() const {
        std::vector<std::uint8_t> out;
        out.push_back(static_cast<std::uint8_t>((version_ & 0x3) | ((type_ & 0x3) << 2) |
                                                ((subtype_ & 0xF) << 4)));
        out.push_back(flags_);
        out.push_back(0x3a); // duration 314
        out.push_back(0x01);
        for (const auto* a : {&addr1_, &addr2_, &addr3_}) {
            out.insert(out.end(), a->octets.begin(), a->octets.end());
        }
        out.push_back(static_cast<std::uint8_t>(seq_ & 0xFF));
        out.push_back(static_cast<std::uint8_t>(seq_ >> 8));
        if ((flags_ & 0x80) != 0) {
            out.insert(out.end(), {0, 0, 0, 0}); // HT control
        }
        out.insert(out.end(), body_.begin(), body_.end());
        return out;
    }

private:
    std::uint8_t version_ = 0;
    std::uint8_t type_ = 0;
    std::uint8_t subtype_;
    std::uint8_t flags_ = 0;
    MacAddress addr1_ = kBroadcast;
    MacAddress addr2_ = kAccessPoint;
    MacAddress addr3_ = kAccessPoint;
    std::uint16_t seq_ = 0;
    std::vector<std::uint8_t> body_;
};

inline inapparency::Observation observe(const std::vector<std::uint8_t>& bytes) {
    inapparency::Observation obs;
    obs.bytes = bytes;
    return obs;
}

} // namespace testing
