#include <vector>

#include "check.hpp"
#include "frame_builder.hpp"
#include "inapparency/parser.hpp"

using namespace inapparency;
using testing::FrameBuilder;
using testing::kAccessPoint;
using testing::kBroadcast;
using testing::kClient;
using testing::observe;

namespace {

// RSN element body: version 1, CCMP group, one CCMP pairwise, one AKM, caps.
std::vector<std::uint8_t> rsn_body(std::uint8_t akm_type, std::uint16_t caps) {
    return {0x01,
            0x00, // version
            0x00,
            0x0f,
            0xac,
            0x04, // group: CCMP
            0x01,
            0x00,
            0x00,
            0x0f,
            0xac,
            0x04, // pairwise: 1 x CCMP
            0x01,
            0x00,
            0x00,
            0x0f,
            0xac,
            akm_type, // AKM: 1 suite
            static_cast<std::uint8_t>(caps & 0xff),
            static_cast<std::uint8_t>(caps >> 8)};
}

FrameBuilder beacon_with_rsn(const std::vector<std::uint8_t>& rsn) {
    FrameBuilder b(ManagementSubtype::Beacon);
    b.beacon_fixed().ssid("lab");
    b.u8(48).u8(static_cast<std::uint8_t>(rsn.size()));
    for (auto byte : rsn) {
        b.u8(byte);
    }
    return b;
}

} // namespace

TEST(empty_observation) {
    std::vector<std::uint8_t> none;
    CHECK(parse_frame(observe(none)).status == ParseStatus::Empty);
}

TEST(one_byte_is_truncated) {
    std::vector<std::uint8_t> one{0xc0};
    CHECK(parse_frame(observe(one)).status == ParseStatus::Truncated);
}

TEST(deauth_with_reason_code) {
    auto bytes = FrameBuilder(ManagementSubtype::Deauthentication)
                     .receiver(kClient)
                     .transmitter(kAccessPoint)
                     .bssid(kAccessPoint)
                     .sequence(1234, 3)
                     .le16(7)
                     .build();
    auto r = parse_frame(observe(bytes));

    CHECK(r.ok());
    CHECK(r.frame.is_management(ManagementSubtype::Deauthentication));
    CHECK(r.frame.receiver() == kClient);
    CHECK(r.frame.transmitter() == kAccessPoint);
    CHECK(r.frame.bssid() == kAccessPoint);
    CHECK_EQ(r.frame.duration, 314);
    CHECK_EQ(r.frame.sequence_number, 1234);
    CHECK_EQ(r.frame.fragment_number, 3);
    CHECK_EQ(r.frame.header_length, 24U);
    CHECK(r.frame.management.reason_code == std::uint16_t{7});
}

TEST(disassoc_with_reason_code) {
    auto bytes = FrameBuilder(ManagementSubtype::Disassociation).le16(8).build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.ok());
    CHECK(r.frame.is_management(ManagementSubtype::Disassociation));
    CHECK(r.frame.management.reason_code == std::uint16_t{8});
}

TEST(deauth_missing_reason_is_truncated) {
    auto bytes = FrameBuilder(ManagementSubtype::Deauthentication).u8(7).build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.status == ParseStatus::Truncated);
    // Header fields are still there for anyone counting these.
    CHECK(r.frame.is_management(ManagementSubtype::Deauthentication));
    CHECK(!r.frame.management.reason_code);
}

TEST(protected_deauth_hides_reason) {
    // A PMF-protected deauth: the body is ciphertext, not a reason code.
    auto bytes = FrameBuilder(ManagementSubtype::Deauthentication)
                     .protect()
                     .bytes({0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04})
                     .build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.ok());
    CHECK(r.frame.control.protected_frame);
    CHECK(!r.frame.management.reason_code);
    CHECK_EQ(r.frame.body.size(), 8U);
}

TEST(header_cut_short_is_truncated) {
    auto bytes = FrameBuilder(ManagementSubtype::Deauthentication).le16(7).build();
    bytes.resize(20);
    CHECK(parse_frame(observe(bytes)).status == ParseStatus::Truncated);
}

TEST(order_bit_adds_ht_control) {
    auto bytes = FrameBuilder(ManagementSubtype::Deauthentication).order().le16(3).build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.ok());
    CHECK_EQ(r.frame.header_length, 28U);
    CHECK(r.frame.management.reason_code == std::uint16_t{3});
}

TEST(bad_protocol_version) {
    auto bytes = FrameBuilder(ManagementSubtype::Beacon).version(1).beacon_fixed().build();
    CHECK(parse_frame(observe(bytes)).status == ParseStatus::BadVersion);
}

TEST(control_and_data_frames_are_unsupported_not_malicious) {
    auto data = FrameBuilder(ManagementSubtype::Beacon).type(2).raw_subtype(0).build();
    auto r = parse_frame(observe(data));
    CHECK(r.status == ParseStatus::Unsupported);
    CHECK(r.frame.control.type == FrameType::Data);

    auto control = FrameBuilder(ManagementSubtype::Beacon).type(1).raw_subtype(11).build();
    r = parse_frame(observe(control));
    CHECK(r.status == ParseStatus::Unsupported);
    CHECK(r.frame.control.type == FrameType::Control);
}

TEST(reserved_management_subtypes_are_unsupported) {
    auto r7 = FrameBuilder(ManagementSubtype::Beacon).raw_subtype(7).build();
    auto r15 = FrameBuilder(ManagementSubtype::Beacon).raw_subtype(15).build();
    CHECK(parse_frame(observe(r7)).status == ParseStatus::Unsupported);
    CHECK(parse_frame(observe(r15)).status == ParseStatus::Unsupported);
}

TEST(beacon_basic_fields) {
    auto bytes = FrameBuilder(ManagementSubtype::Beacon)
                     .beacon_fixed(102, 0x1431)
                     .ssid("cafe-wifi")
                     .element(1, {0x82, 0x84, 0x8b, 0x96}) // supported rates, ignored
                     .element(3, {6})
                     .build();
    auto r = parse_frame(observe(bytes));
    const auto& m = r.frame.management;

    CHECK(r.ok());
    CHECK(r.frame.receiver() == kBroadcast);
    CHECK(m.beacon_interval == std::uint16_t{102});
    CHECK(m.capability_info == std::uint16_t{0x1431});
    CHECK(m.ssid.has_value());
    CHECK(m.ssid && m.ssid->view() == "cafe-wifi");
    CHECK(m.ds_channel == std::uint8_t{6});
    CHECK(!m.rsn);
    CHECK(!m.elements_truncated);
    CHECK(!m.elements_malformed);
}

TEST(beacon_without_fixed_fields_is_truncated) {
    auto bytes = FrameBuilder(ManagementSubtype::Beacon).bytes({0, 0, 0, 0, 0}).build();
    CHECK(parse_frame(observe(bytes)).status == ParseStatus::Truncated);
}

TEST(hidden_ssid_beacon) {
    auto bytes =
        FrameBuilder(ManagementSubtype::Beacon).beacon_fixed().element(0, {0, 0, 0, 0}).build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.ok());
    CHECK(r.frame.management.ssid && r.frame.management.ssid->is_hidden());
}

TEST(probe_response_parses_like_beacon) {
    auto bytes = FrameBuilder(ManagementSubtype::ProbeResponse)
                     .receiver(kClient)
                     .beacon_fixed()
                     .ssid("lab")
                     .build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.ok());
    CHECK(r.frame.management.ssid && r.frame.management.ssid->view() == "lab");
}

TEST(probe_request_wildcard_and_named) {
    auto wildcard = FrameBuilder(ManagementSubtype::ProbeRequest)
                        .transmitter(kClient)
                        .bssid(kBroadcast)
                        .ssid("")
                        .build();
    auto r = parse_frame(observe(wildcard));
    CHECK(r.ok());
    CHECK(r.frame.transmitter() == kClient);
    CHECK(r.frame.management.ssid && r.frame.management.ssid->length == 0);

    auto named = FrameBuilder(ManagementSubtype::ProbeRequest).ssid("home").build();
    r = parse_frame(observe(named));
    CHECK(r.frame.management.ssid && r.frame.management.ssid->view() == "home");
}

TEST(element_running_past_end_is_flagged_not_fatal) {
    auto bytes = FrameBuilder(ManagementSubtype::Beacon)
                     .beacon_fixed()
                     .ssid("ok")
                     .bytes({3, 5, 6}) // DS element claims 5 bytes, has 1
                     .build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.ok());
    CHECK(r.frame.management.elements_truncated);
    CHECK(r.frame.management.ssid && r.frame.management.ssid->view() == "ok");
    CHECK(!r.frame.management.ds_channel);
}

TEST(lone_element_id_byte_is_flagged) {
    auto bytes = FrameBuilder(ManagementSubtype::Beacon).beacon_fixed().u8(0).build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.ok());
    CHECK(r.frame.management.elements_truncated);
}

TEST(oversized_ssid_is_malformed) {
    std::vector<std::uint8_t> long_name(33, 'a');
    FrameBuilder b(ManagementSubtype::Beacon);
    b.beacon_fixed().u8(0).u8(33);
    for (auto c : long_name) {
        b.u8(c);
    }
    auto r = parse_frame(observe(b.build()));
    CHECK(r.ok());
    CHECK(r.frame.management.elements_malformed);
    CHECK(!r.frame.management.ssid);
}

TEST(wrong_length_ds_element_is_malformed) {
    auto bytes = FrameBuilder(ManagementSubtype::Beacon).beacon_fixed().element(3, {6, 7}).build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.frame.management.elements_malformed);
    CHECK(!r.frame.management.ds_channel);
}

TEST(only_first_ssid_element_is_kept) {
    auto bytes =
        FrameBuilder(ManagementSubtype::Beacon).beacon_fixed().ssid("first").ssid("second").build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.frame.management.ssid && r.frame.management.ssid->view() == "first");
}

TEST(rsn_wpa3_requires_pmf) {
    // AKM 8 = SAE, caps bit 6 (MFPR) and bit 7 (MFPC) set.
    auto r = parse_frame(observe(beacon_with_rsn(rsn_body(akm::sae, 0x00c0)).build()));
    const auto& rsn = r.frame.management.rsn;
    CHECK(r.ok());
    CHECK(rsn.has_value());
    CHECK(rsn && rsn->mfp_required && rsn->mfp_capable);
    CHECK(rsn && rsn->advertises_akm(akm::sae));
    CHECK(rsn && !rsn->advertises_akm(akm::psk));
}

TEST(rsn_wpa2_psk_without_pmf) {
    auto r = parse_frame(observe(beacon_with_rsn(rsn_body(akm::psk, 0x0000)).build()));
    const auto& rsn = r.frame.management.rsn;
    CHECK(rsn && !rsn->mfp_required && !rsn->mfp_capable);
    CHECK(rsn && rsn->advertises_akm(akm::psk));
}

TEST(rsn_pmf_capable_but_optional) {
    auto r = parse_frame(observe(beacon_with_rsn(rsn_body(akm::psk, 0x0080)).build()));
    const auto& rsn = r.frame.management.rsn;
    CHECK(rsn && rsn->mfp_capable && !rsn->mfp_required);
}

TEST(rsn_may_stop_at_field_boundary) {
    // Version only: legal, nothing advertised.
    auto r = parse_frame(observe(beacon_with_rsn({0x01, 0x00}).build()));
    CHECK(r.frame.management.rsn.has_value());
    CHECK(!r.frame.management.elements_malformed);

    // Version + group cipher only.
    r = parse_frame(observe(beacon_with_rsn({0x01, 0x00, 0x00, 0x0f, 0xac, 0x04}).build()));
    CHECK(r.frame.management.rsn.has_value());
}

TEST(rsn_cut_mid_field_is_malformed) {
    auto body = rsn_body(akm::sae, 0x00c0);
    body.resize(body.size() - 1); // half a capabilities field
    auto r = parse_frame(observe(beacon_with_rsn(body).build()));
    CHECK(!r.frame.management.rsn);
    CHECK(r.frame.management.elements_malformed);
}

TEST(rsn_suite_count_larger_than_element) {
    std::vector<std::uint8_t> body{0x01, 0x00, 0x00, 0x0f,
                                   0xac, 0x04, 0xff, 0xff, // 65535 pairwise suites
                                   0x00, 0x0f, 0xac, 0x04};
    auto r = parse_frame(observe(beacon_with_rsn(body).build()));
    CHECK(!r.frame.management.rsn);
    CHECK(r.frame.management.elements_malformed);
}

TEST(rsn_wrong_version_is_malformed) {
    auto body = rsn_body(akm::psk, 0);
    body[0] = 2;
    auto r = parse_frame(observe(beacon_with_rsn(body).build()));
    CHECK(!r.frame.management.rsn);
    CHECK(r.frame.management.elements_malformed);
}

TEST(rsn_vendor_akm_is_not_counted) {
    auto body = rsn_body(akm::psk, 0);
    body[14] = 0x00; // change the AKM OUI away from 00-0F-AC
    body[15] = 0x50;
    body[16] = 0xf2;
    auto r = parse_frame(observe(beacon_with_rsn(body).build()));
    CHECK(r.frame.management.rsn && r.frame.management.rsn->akm_suites == 0);
}

TEST(fcs_is_stripped_when_present) {
    auto bytes = FrameBuilder(ManagementSubtype::Deauthentication).le16(7).build();
    bytes.insert(bytes.end(), {0x11, 0x22, 0x33, 0x44});
    auto obs = observe(bytes);
    obs.includes_fcs = true;
    auto r = parse_frame(obs);
    CHECK(r.ok());
    CHECK_EQ(r.frame.body.size(), 2U);
}

TEST(fcs_on_tiny_buffer) {
    std::vector<std::uint8_t> three{1, 2, 3};
    auto obs = observe(three);
    obs.includes_fcs = true;
    CHECK(parse_frame(obs).status == ParseStatus::Truncated);
}

TEST(capture_truncation_is_reported) {
    auto bytes = FrameBuilder(ManagementSubtype::Beacon).beacon_fixed().ssid("lab").build();
    auto obs = observe(bytes);
    obs.original_length = bytes.size() + 40;
    obs.includes_fcs = true; // the FCS was in the part that got cut
    auto r = parse_frame(obs);
    CHECK(r.ok());
    CHECK(r.capture_truncated);
    CHECK(r.frame.management.ssid && r.frame.management.ssid->view() == "lab");
}

TEST(status_names) {
    CHECK(std::string_view(to_string(ParseStatus::Ok)) == "ok");
    CHECK(std::string_view(to_string(ParseStatus::Unsupported)) == "unsupported");
}
