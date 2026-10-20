#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace inapparency {

enum class FrameType : std::uint8_t {
    Management = 0,
    Control = 1,
    Data = 2,
    Extension = 3,
};

enum class ManagementSubtype : std::uint8_t {
    AssociationRequest = 0,
    AssociationResponse = 1,
    ReassociationRequest = 2,
    ReassociationResponse = 3,
    ProbeRequest = 4,
    ProbeResponse = 5,
    TimingAdvertisement = 6,
    Beacon = 8,
    Atim = 9,
    Disassociation = 10,
    Authentication = 11,
    Deauthentication = 12,
    Action = 13,
    ActionNoAck = 14,
};

struct MacAddress {
    std::array<std::uint8_t, 6> octets{};

    bool is_broadcast() const;
    bool is_multicast() const { return (octets[0] & 0x01U) != 0; }
    // Randomized client MACs usually have this bit set.
    bool is_locally_administered() const { return (octets[0] & 0x02U) != 0; }

    // "aa:bb:cc:dd:ee:ff" plus a terminating null.
    std::array<char, 18> to_string() const;

    friend bool operator==(const MacAddress&, const MacAddress&) = default;
};

struct FrameControl {
    std::uint8_t protocol_version = 0;
    FrameType type = FrameType::Management;
    std::uint8_t subtype = 0;
    bool to_ds = false;
    bool from_ds = false;
    bool more_fragments = false;
    bool retry = false;
    bool power_management = false;
    bool more_data = false;
    bool protected_frame = false;
    bool order = false;

    static FrameControl decode(std::uint16_t raw);
};

struct Ssid {
    std::array<std::uint8_t, 32> bytes{};
    std::uint8_t length = 0;

    std::string_view view() const;
    // Empty, or filled with zero bytes. Both are common ways to hide a name.
    bool is_hidden() const;

    friend bool operator==(const Ssid& a, const Ssid& b) {
        return a.length == b.length && a.view() == b.view();
    }
};

// The parts of an RSN element that detection cares about.
struct RsnInfo {
    bool mfp_capable = false;  // PMF / 802.11w supported
    bool mfp_required = false; // PMF required, e.g. WPA3
    // Bit n set when AKM suite 00-0F-AC:n is advertised (n < 32).
    std::uint32_t akm_suites = 0;

    bool advertises_akm(std::uint8_t suite) const {
        return suite < 32 && (akm_suites & (std::uint32_t{1} << suite)) != 0;
    }
};

namespace akm {
inline constexpr std::uint8_t ieee8021x = 1;
inline constexpr std::uint8_t psk = 2;
inline constexpr std::uint8_t sae = 8;
} // namespace akm

// Fields pulled out of management frame bodies. Everything is optional
// because frames often leave things out, and protected frames hide them.
struct ManagementInfo {
    std::optional<std::uint16_t> reason_code; // deauth / disassoc
    std::optional<std::uint16_t> status_code; // authentication, (re)assoc response
    std::optional<std::uint16_t> auth_algorithm;
    std::optional<std::uint16_t> auth_sequence;
    std::optional<std::uint16_t> listen_interval; // (re)assoc request
    std::optional<std::uint16_t> association_id;  // (re)assoc response, 1-2007
    std::optional<MacAddress> current_ap;         // reassoc request
    std::optional<std::uint8_t> action_category;
    std::optional<std::uint16_t> beacon_interval;
    std::optional<std::uint16_t> capability_info;
    std::optional<Ssid> ssid;
    std::optional<std::uint8_t> ds_channel;
    std::optional<RsnInfo> rsn;

    // An element claimed more bytes than the frame had left.
    bool elements_truncated = false;
    // An element had a length that is impossible for its ID.
    bool elements_malformed = false;
};

struct ParsedFrame {
    FrameControl control;
    std::uint16_t duration = 0;

    // For management frames: receiver, transmitter, BSSID.
    MacAddress addr1;
    MacAddress addr2;
    MacAddress addr3;

    std::uint16_t sequence_number = 0;
    std::uint8_t fragment_number = 0;

    std::size_t header_length = 0;
    std::span<const std::uint8_t> body;

    ManagementInfo management;

    bool is_management(ManagementSubtype subtype) const {
        return control.type == FrameType::Management &&
               control.subtype == static_cast<std::uint8_t>(subtype);
    }

    const MacAddress& receiver() const { return addr1; }
    const MacAddress& transmitter() const { return addr2; }
    const MacAddress& bssid() const { return addr3; }
};

} // namespace inapparency
