// Management subtypes beyond deauth/beacon/probe.

#include "check.hpp"
#include "frame_builder.hpp"
#include "inapparency/parser.hpp"

using namespace inapparency;
using testing::FrameBuilder;
using testing::kAccessPoint;
using testing::kClient;
using testing::mac;
using testing::observe;

TEST(auth_open_system) {
    auto bytes = FrameBuilder(ManagementSubtype::Authentication)
                     .receiver(kAccessPoint)
                     .transmitter(kClient)
                     .le16(0) // open system
                     .le16(1) // first frame
                     .le16(0) // success
                     .build();
    auto r = parse_frame(observe(bytes));
    const auto& m = r.frame.management;
    CHECK(r.ok());
    CHECK(m.auth_algorithm == std::uint16_t{0});
    CHECK(m.auth_sequence == std::uint16_t{1});
    CHECK(m.status_code == std::uint16_t{0});
}

TEST(auth_sae_body_is_not_read_as_elements) {
    // SAE commit: algorithm 3, then group + scalar + element, not IEs.
    auto bytes = FrameBuilder(ManagementSubtype::Authentication)
                     .le16(3)
                     .le16(1)
                     .le16(0)
                     .bytes({0x13, 0x00, 0xff, 0xff, 0xff, 0x01, 0x02})
                     .build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.ok());
    CHECK(r.frame.management.auth_algorithm == std::uint16_t{3});
    CHECK(!r.frame.management.elements_truncated);
    CHECK(!r.frame.management.elements_malformed);
}

TEST(auth_too_short) {
    auto bytes = FrameBuilder(ManagementSubtype::Authentication).le16(0).le16(1).build();
    CHECK(parse_frame(observe(bytes)).status == ParseStatus::Truncated);
}

TEST(association_request) {
    auto bytes = FrameBuilder(ManagementSubtype::AssociationRequest)
                     .receiver(kAccessPoint)
                     .transmitter(kClient)
                     .le16(0x0431)
                     .le16(10)
                     .ssid("home")
                     .build();
    auto r = parse_frame(observe(bytes));
    const auto& m = r.frame.management;
    CHECK(r.ok());
    CHECK(m.capability_info == std::uint16_t{0x0431});
    CHECK(m.listen_interval == std::uint16_t{10});
    CHECK(m.ssid && m.ssid->view() == "home");
}

TEST(reassociation_request_has_current_ap) {
    auto old_ap = mac(0x02, 0x77, 0x77, 0x77, 0x77, 0x77);
    FrameBuilder b(ManagementSubtype::ReassociationRequest);
    b.le16(0x0431).le16(10);
    for (auto o : old_ap.octets) {
        b.u8(o);
    }
    b.ssid("home");
    auto r = parse_frame(observe(b.build()));
    CHECK(r.ok());
    CHECK(r.frame.management.current_ap == old_ap);
    CHECK(r.frame.management.ssid && r.frame.management.ssid->view() == "home");
}

TEST(reassociation_request_too_short) {
    auto bytes =
        FrameBuilder(ManagementSubtype::ReassociationRequest).le16(1).le16(1).u8(2).build();
    CHECK(parse_frame(observe(bytes)).status == ParseStatus::Truncated);
}

TEST(association_response_masks_aid) {
    auto bytes = FrameBuilder(ManagementSubtype::AssociationResponse)
                     .le16(0x0411)
                     .le16(0)
                     .le16(0xC005) // top two bits are always set on the air
                     .element(1, {0x82})
                     .build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.ok());
    CHECK(r.frame.management.status_code == std::uint16_t{0});
    CHECK(r.frame.management.association_id == std::uint16_t{5});
}

TEST(reassociation_response_refused) {
    auto bytes =
        FrameBuilder(ManagementSubtype::ReassociationResponse).le16(0).le16(17).le16(0).build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.ok());
    CHECK(r.frame.management.status_code == std::uint16_t{17});
}

TEST(association_response_too_short) {
    auto bytes = FrameBuilder(ManagementSubtype::AssociationResponse).le16(0).le16(0).build();
    CHECK(parse_frame(observe(bytes)).status == ParseStatus::Truncated);
}

TEST(action_category) {
    auto sa_query = FrameBuilder(ManagementSubtype::Action).u8(8).u8(0).le16(0x1234).build();
    auto r = parse_frame(observe(sa_query));
    CHECK(r.ok());
    CHECK(r.frame.management.action_category == std::uint8_t{8});

    auto no_ack = FrameBuilder(ManagementSubtype::ActionNoAck).u8(21).build();
    CHECK(parse_frame(observe(no_ack)).frame.management.action_category == std::uint8_t{21});

    auto empty = FrameBuilder(ManagementSubtype::Action).build();
    CHECK(parse_frame(observe(empty)).status == ParseStatus::Truncated);
}

TEST(protected_action_body_is_not_read) {
    auto bytes = FrameBuilder(ManagementSubtype::Action).protect().bytes({1, 2, 3, 4}).build();
    auto r = parse_frame(observe(bytes));
    CHECK(r.ok());
    CHECK(!r.frame.management.action_category);
}

TEST(every_prefix_of_every_subtype) {
    // Each subtype cut at every length: never crashes, never claims fields
    // it didn't have the bytes for.
    for (std::uint8_t subtype = 0; subtype < 16; ++subtype) {
        auto full = FrameBuilder(ManagementSubtype::Beacon)
                        .raw_subtype(subtype)
                        .bytes({1, 2, 3,   4,   5,   6, 7, 8, 9,  10, 11, 12,
                                0, 3, 'a', 'b', 'c', 3, 1, 6, 48, 2,  1,  0})
                        .build();
        for (std::size_t len = 0; len <= full.size(); ++len) {
            std::vector<std::uint8_t> cut(full.begin(),
                                          full.begin() + static_cast<std::ptrdiff_t>(len));
            cut.shrink_to_fit();
            auto r = parse_frame(observe(cut));
            CHECK(r.frame.body.size() <= cut.size());
            if (len < 24) {
                CHECK(!r.ok());
            }
        }
    }
}
