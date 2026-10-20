#include <cstring>

#include "check.hpp"
#include "frame_builder.hpp"
#include "inapparency/event.hpp"
#include "inapparency/frame.hpp"

using namespace inapparency;
using testing::mac;

TEST(mac_formats_lowercase_with_colons) {
    auto text = mac(0x00, 0x1a, 0x2B, 0xff, 0x09, 0x10).to_string();
    CHECK(std::strcmp(text.data(), "00:1a:2b:ff:09:10") == 0);
}

TEST(mac_flags) {
    CHECK(testing::kBroadcast.is_broadcast());
    CHECK(testing::kBroadcast.is_multicast());
    CHECK(!testing::kAccessPoint.is_broadcast());
    CHECK(!testing::kAccessPoint.is_multicast());
    CHECK(testing::kAccessPoint.is_locally_administered());
    CHECK(!mac(0x00, 0x11, 0x22, 0x33, 0x44, 0x55).is_locally_administered());
}

TEST(frame_control_decodes_every_field) {
    // Deauth (type 0, subtype 12), every flag set.
    auto fc = FrameControl::decode(0xFFC0);
    CHECK_EQ(fc.protocol_version, 0);
    CHECK(fc.type == FrameType::Management);
    CHECK_EQ(fc.subtype, 12);
    CHECK(fc.to_ds && fc.from_ds && fc.more_fragments && fc.retry);
    CHECK(fc.power_management && fc.more_data && fc.protected_frame && fc.order);

    // Data frame (type 2), no flags.
    fc = FrameControl::decode(0x0008);
    CHECK(fc.type == FrameType::Data);
    CHECK_EQ(fc.subtype, 0);
    CHECK(!fc.to_ds && !fc.protected_frame && !fc.order);
}

TEST(ssid_hidden_detection) {
    Ssid empty;
    CHECK(empty.is_hidden());

    Ssid zeros;
    zeros.length = 6;
    CHECK(zeros.is_hidden());

    Ssid named;
    named.length = 4;
    std::memcpy(named.bytes.data(), "home", 4);
    CHECK(!named.is_hidden());
    CHECK(named.view() == "home");
}

TEST(severity_names) {
    CHECK(std::strcmp(to_string(Severity::Info), "info") == 0);
    CHECK(std::strcmp(to_string(Severity::Critical), "critical") == 0);
}
