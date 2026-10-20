#include <cstring>
#include <string>

#include "check.hpp"
#include "frame_builder.hpp"
#include "inapparency/serial/format.hpp"

using namespace inapparency;
using namespace inapparency::serial;

namespace {

DetectionEvent sample_event() {
    DetectionEvent e;
    e.rule_id = 1;
    e.rule_name = "deauth-burst";
    e.timestamp_ms = 12'345;
    e.window_ms = 5000;
    e.severity = Severity::High;
    e.confidence = 75;
    e.evidence_count = 20;
    e.bssid = testing::kAccessPoint;
    e.source = testing::kAccessPoint;
    e.channel = 6;
    e.explanation = "Something \"quoted\" happened.";
    return e;
}

std::string text(const DetectionEvent& e, Format f) {
    char buf[512];
    std::size_t n = format_event(e, f, buf, sizeof buf);
    CHECK_EQ(n, std::strlen(buf));
    return buf;
}

bool has(const std::string& s, const char* part) {
    return s.find(part) != std::string::npos;
}

} // namespace

TEST(serial_event_text) {
    auto line = text(sample_event(), Format::Text);
    CHECK(has(line, "[12.345] HIGH deauth-burst confidence=75 evidence=20/5000ms"));
    CHECK(has(line, "bssid=02:11:22:33:44:55"));
    CHECK(!has(line, "src=")); // same as bssid, not repeated
    CHECK(has(line, "ch=6"));
    CHECK(line.back() == '\n');
}

TEST(serial_event_json) {
    auto line = text(sample_event(), Format::Json);
    CHECK(has(line, "{\"type\":\"event\",\"t_ms\":12345,\"rule\":\"deauth-burst\""));
    CHECK(has(line, "\"severity\":\"high\",\"confidence\":75"));
    CHECK(has(line, "\"source\":\"02:11:22:33:44:55\""));
    CHECK(has(line, "\"why\":\"Something \\\"quoted\\\" happened.\"}"));
    CHECK(line.back() == '\n');
}

TEST(serial_event_leaves_out_missing_fields) {
    DetectionEvent e = sample_event();
    e.bssid.reset();
    e.source.reset();
    e.channel.reset();
    auto t = text(e, Format::Text);
    auto j = text(e, Format::Json);
    CHECK(!has(t, "bssid") && !has(t, "ch="));
    CHECK(!has(j, "bssid") && !has(j, "channel") && !has(j, "source"));
}

TEST(serial_line_cut_short_safely) {
    char buf[24];
    std::memset(buf, 'x', sizeof buf);
    std::size_t n = format_event(sample_event(), Format::Json, buf, sizeof buf);
    CHECK_EQ(n, 23U);
    CHECK_EQ(buf[22], '\n');
    CHECK_EQ(buf[23], '\0');

    char one[1] = {'x'};
    CHECK_EQ(format_event(sample_event(), Format::Text, one, 1), 0U);
    CHECK_EQ(one[0], '\0');
    CHECK_EQ(format_event(sample_event(), Format::Text, nullptr, 0), 0U);
}

TEST(serial_status_lines) {
    DetectorStats stats;
    stats.observations = 1000;
    stats.ok = 900;
    stats.events = 2;
    Status s;
    s.uptime_ms = 60'000;
    s.stats = &stats;
    s.dropped = 3;
    s.channel = 11;
    s.free_heap = 200'000;

    char buf[512];
    format_status(s, Format::Text, buf, sizeof buf);
    std::string t = buf;
    CHECK(has(t, "[60.000] status frames=1000 ok=900"));
    CHECK(has(t, "events=2 dropped=3"));
    CHECK(has(t, "ch=11 heap=200000"));
    CHECK(!has(t, "heap_min"));

    format_status(s, Format::Json, buf, sizeof buf);
    std::string j = buf;
    CHECK(has(j, "{\"type\":\"status\",\"uptime_ms\":60000,\"frames\":1000"));
    CHECK(has(j, "\"channel\":11,\"free_heap\":200000}"));

    Status bare;
    format_status(bare, Format::Text, buf, sizeof buf);
    CHECK(has(std::string(buf), "frames=0"));
}

TEST(serial_coverage_and_suppressed) {
    DetectionEvent e = sample_event();
    e.coverage_percent = 33;
    CHECK(has(text(e, Format::Text), "ch=6 coverage=33% |"));
    CHECK(has(text(e, Format::Json), "\"coverage\":33,"));

    Status s;
    s.suppressed = 12;
    s.stack_free = 2048;
    char buf[512];
    format_status(s, Format::Text, buf, sizeof buf);
    CHECK(has(std::string(buf), "stack_free=2048 suppressed=12"));
    format_status(s, Format::Json, buf, sizeof buf);
    CHECK(has(std::string(buf), "\"stack_free\":2048,\"suppressed\":12}"));
}
