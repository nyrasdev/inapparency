#include "inapparency/parser.hpp"

namespace inapparency {
namespace {

using Bytes = std::span<const std::uint8_t>;

constexpr std::size_t kFcsLength = 4;
constexpr std::size_t kFrameControlLength = 2;
constexpr std::size_t kManagementHeaderLength = 24;
constexpr std::size_t kHtControlLength = 4;
constexpr std::size_t kReasonCodeLength = 2;
constexpr std::size_t kBeaconFixedLength = 12;         // timestamp, interval, capability
constexpr std::size_t kAuthFixedLength = 6;            // algorithm, sequence, status
constexpr std::size_t kAssocRequestFixedLength = 4;    // capability, listen interval
constexpr std::size_t kReassocRequestFixedLength = 10; // + current AP
constexpr std::size_t kAssocResponseFixedLength = 6;   // capability, status, AID

constexpr std::uint8_t kElementSsid = 0;
constexpr std::uint8_t kElementDsParameterSet = 3;
constexpr std::uint8_t kElementRsn = 48;
constexpr std::size_t kMaxSsidLength = 32;

constexpr std::uint8_t kSubtypeReserved7 = 7;
constexpr std::uint8_t kSubtypeReserved15 = 15;

std::uint16_t read_le16(Bytes b, std::size_t offset) {
    return static_cast<std::uint16_t>(b[offset] | (b[offset + 1] << 8));
}

MacAddress read_mac(Bytes b, std::size_t offset) {
    MacAddress mac;
    for (std::size_t i = 0; i < mac.octets.size(); ++i) {
        mac.octets[i] = b[offset + i];
    }
    return mac;
}

bool is_ieee_suite(Bytes b, std::size_t offset) {
    return b[offset] == 0x00 && b[offset + 1] == 0x0F && b[offset + 2] == 0xAC;
}

// RSN element layout: version, group cipher, pairwise ciphers, AKM suites,
// capabilities, then optional stuff we ignore. Everything after the version
// may be left out, but only at a field boundary.
std::optional<RsnInfo> parse_rsn(Bytes d) {
    RsnInfo info;
    std::size_t p = 0;

    if (d.size() < 2 || read_le16(d, 0) != 1) {
        return std::nullopt;
    }
    p = 2;
    if (d.size() == p) {
        return info;
    }

    if (d.size() - p < 4) {
        return std::nullopt;
    }
    p += 4; // group data cipher
    if (d.size() == p) {
        return info;
    }

    if (d.size() - p < 2) {
        return std::nullopt;
    }
    std::size_t pairwise = read_le16(d, p);
    p += 2;
    if ((d.size() - p) / 4 < pairwise) {
        return std::nullopt;
    }
    p += pairwise * 4;
    if (d.size() == p) {
        return info;
    }

    if (d.size() - p < 2) {
        return std::nullopt;
    }
    std::size_t akm_count = read_le16(d, p);
    p += 2;
    if ((d.size() - p) / 4 < akm_count) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < akm_count; ++i, p += 4) {
        std::uint8_t type = d[p + 3];
        if (is_ieee_suite(d, p) && type < 32) {
            info.akm_suites |= (std::uint32_t{1} << type);
        }
    }
    if (d.size() == p) {
        return info;
    }

    if (d.size() - p < 2) {
        return std::nullopt;
    }
    std::uint16_t caps = read_le16(d, p);
    info.mfp_required = (caps & (1U << 6)) != 0;
    info.mfp_capable = (caps & (1U << 7)) != 0;
    return info;
}

void parse_elements(Bytes elements, ManagementInfo& info) {
    std::size_t offset = 0;
    while (offset < elements.size()) {
        if (elements.size() - offset < 2) {
            info.elements_truncated = true;
            return;
        }
        std::uint8_t id = elements[offset];
        std::size_t length = elements[offset + 1];
        offset += 2;
        if (elements.size() - offset < length) {
            info.elements_truncated = true;
            return;
        }
        Bytes data = elements.subspan(offset, length);
        offset += length;

        switch (id) {
        case kElementSsid:
            if (length > kMaxSsidLength) {
                info.elements_malformed = true;
            } else if (!info.ssid) {
                Ssid ssid;
                ssid.length = static_cast<std::uint8_t>(length);
                for (std::size_t i = 0; i < length; ++i) {
                    ssid.bytes[i] = data[i];
                }
                info.ssid = ssid;
            }
            break;
        case kElementDsParameterSet:
            if (length != 1) {
                info.elements_malformed = true;
            } else if (!info.ds_channel) {
                info.ds_channel = data[0];
            }
            break;
        case kElementRsn:
            if (!info.rsn) {
                info.rsn = parse_rsn(data);
                if (!info.rsn) {
                    info.elements_malformed = true;
                }
            }
            break;
        default:
            break;
        }
    }
}

} // namespace

const char* to_string(ParseStatus status) {
    switch (status) {
    case ParseStatus::Ok:
        return "ok";
    case ParseStatus::Empty:
        return "empty";
    case ParseStatus::Truncated:
        return "truncated";
    case ParseStatus::BadVersion:
        return "bad-version";
    case ParseStatus::Unsupported:
        return "unsupported";
    }
    return "unknown";
}

ParseResult parse_frame(const Observation& observation) {
    ParseResult result;
    Bytes bytes = observation.bytes;

    if (observation.original_length && *observation.original_length > bytes.size()) {
        result.capture_truncated = true;
    }

    // A cut-off capture lost its FCS along with the tail, so only strip it
    // when the frame arrived whole.
    if (observation.includes_fcs && !result.capture_truncated) {
        if (bytes.size() < kFcsLength) {
            result.status = bytes.empty() ? ParseStatus::Empty : ParseStatus::Truncated;
            return result;
        }
        bytes = bytes.first(bytes.size() - kFcsLength);
    }

    if (bytes.empty()) {
        result.status = ParseStatus::Empty;
        return result;
    }
    if (bytes.size() < kFrameControlLength) {
        result.status = ParseStatus::Truncated;
        return result;
    }

    ParsedFrame& frame = result.frame;
    frame.control = FrameControl::decode(read_le16(bytes, 0));

    if (frame.control.protocol_version != 0) {
        result.status = ParseStatus::BadVersion;
        return result;
    }
    if (frame.control.type != FrameType::Management || frame.control.subtype == kSubtypeReserved7 ||
        frame.control.subtype == kSubtypeReserved15) {
        result.status = ParseStatus::Unsupported;
        return result;
    }

    std::size_t header_length =
        kManagementHeaderLength + (frame.control.order ? kHtControlLength : 0);
    if (bytes.size() < header_length) {
        result.status = ParseStatus::Truncated;
        return result;
    }

    frame.header_length = header_length;
    frame.duration = read_le16(bytes, 2);
    frame.addr1 = read_mac(bytes, 4);
    frame.addr2 = read_mac(bytes, 10);
    frame.addr3 = read_mac(bytes, 16);
    std::uint16_t sequence_control = read_le16(bytes, 22);
    frame.fragment_number = static_cast<std::uint8_t>(sequence_control & 0xFU);
    frame.sequence_number = static_cast<std::uint16_t>(sequence_control >> 4);
    frame.body = bytes.subspan(header_length);

    // Protected management frames have an encrypted body. Nothing in it can
    // be trusted or read, so stop at the header.
    if (frame.control.protected_frame) {
        result.status = ParseStatus::Ok;
        return result;
    }

    ManagementInfo& info = frame.management;
    Bytes body = frame.body;

    switch (static_cast<ManagementSubtype>(frame.control.subtype)) {
    case ManagementSubtype::Deauthentication:
    case ManagementSubtype::Disassociation:
        if (body.size() < kReasonCodeLength) {
            result.status = ParseStatus::Truncated;
            return result;
        }
        info.reason_code = read_le16(body, 0);
        break;
    case ManagementSubtype::Beacon:
    case ManagementSubtype::ProbeResponse:
        if (body.size() < kBeaconFixedLength) {
            result.status = ParseStatus::Truncated;
            return result;
        }
        info.beacon_interval = read_le16(body, 8);
        info.capability_info = read_le16(body, 10);
        parse_elements(body.subspan(kBeaconFixedLength), info);
        break;
    case ManagementSubtype::ProbeRequest:
        parse_elements(body, info);
        break;
    case ManagementSubtype::Authentication:
        if (body.size() < kAuthFixedLength) {
            result.status = ParseStatus::Truncated;
            return result;
        }
        info.auth_algorithm = read_le16(body, 0);
        info.auth_sequence = read_le16(body, 2);
        info.status_code = read_le16(body, 4);
        // What follows depends on the algorithm (SAE carries its own data,
        // not elements), so it's left alone.
        break;
    case ManagementSubtype::AssociationRequest:
        if (body.size() < kAssocRequestFixedLength) {
            result.status = ParseStatus::Truncated;
            return result;
        }
        info.capability_info = read_le16(body, 0);
        info.listen_interval = read_le16(body, 2);
        parse_elements(body.subspan(kAssocRequestFixedLength), info);
        break;
    case ManagementSubtype::ReassociationRequest:
        if (body.size() < kReassocRequestFixedLength) {
            result.status = ParseStatus::Truncated;
            return result;
        }
        info.capability_info = read_le16(body, 0);
        info.listen_interval = read_le16(body, 2);
        info.current_ap = read_mac(body, 4);
        parse_elements(body.subspan(kReassocRequestFixedLength), info);
        break;
    case ManagementSubtype::AssociationResponse:
    case ManagementSubtype::ReassociationResponse:
        if (body.size() < kAssocResponseFixedLength) {
            result.status = ParseStatus::Truncated;
            return result;
        }
        info.capability_info = read_le16(body, 0);
        info.status_code = read_le16(body, 2);
        info.association_id = static_cast<std::uint16_t>(read_le16(body, 4) & 0x3FFFU);
        parse_elements(body.subspan(kAssocResponseFixedLength), info);
        break;
    case ManagementSubtype::Action:
    case ManagementSubtype::ActionNoAck:
        if (body.empty()) {
            result.status = ParseStatus::Truncated;
            return result;
        }
        info.action_category = body[0];
        break;
    default:
        break;
    }

    result.status = ParseStatus::Ok;
    return result;
}

} // namespace inapparency
