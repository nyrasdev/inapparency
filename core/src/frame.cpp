#include "inapparency/frame.hpp"

#include "inapparency/event.hpp"

namespace inapparency {

bool MacAddress::is_broadcast() const {
    for (auto octet : octets) {
        if (octet != 0xFF) {
            return false;
        }
    }
    return true;
}

std::array<char, 18> MacAddress::to_string() const {
    constexpr char hex[] = "0123456789abcdef";
    std::array<char, 18> out{};
    std::size_t pos = 0;
    for (std::size_t i = 0; i < octets.size(); ++i) {
        out[pos++] = hex[octets[i] >> 4];
        out[pos++] = hex[octets[i] & 0x0F];
        if (i + 1 < octets.size()) {
            out[pos++] = ':';
        }
    }
    out[pos] = '\0';
    return out;
}

FrameControl FrameControl::decode(std::uint16_t raw) {
    FrameControl fc;
    fc.protocol_version = static_cast<std::uint8_t>(raw & 0x3U);
    fc.type = static_cast<FrameType>((raw >> 2) & 0x3U);
    fc.subtype = static_cast<std::uint8_t>((raw >> 4) & 0xFU);
    fc.to_ds = (raw & (1U << 8)) != 0;
    fc.from_ds = (raw & (1U << 9)) != 0;
    fc.more_fragments = (raw & (1U << 10)) != 0;
    fc.retry = (raw & (1U << 11)) != 0;
    fc.power_management = (raw & (1U << 12)) != 0;
    fc.more_data = (raw & (1U << 13)) != 0;
    fc.protected_frame = (raw & (1U << 14)) != 0;
    fc.order = (raw & (1U << 15)) != 0;
    return fc;
}

std::string_view Ssid::view() const {
    return {reinterpret_cast<const char*>(bytes.data()), length};
}

bool Ssid::is_hidden() const {
    for (std::size_t i = 0; i < length; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

const char* to_string(Severity severity) {
    switch (severity) {
    case Severity::Info:
        return "info";
    case Severity::Low:
        return "low";
    case Severity::Medium:
        return "medium";
    case Severity::High:
        return "high";
    case Severity::Critical:
        return "critical";
    }
    return "unknown";
}

} // namespace inapparency
