#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>

#include <unistd.h>

#include "check.hpp"
#include "inapparency/fanout.hpp"
#include "inapparency/storage/event_log.hpp"
#include "scenario.hpp"

using namespace inapparency;
using namespace inapparency::storage;

namespace {

class MemoryFs final : public FileSystem {
public:
    bool append(const char* path, const char* data, std::size_t length) override {
        if (fail_writes) {
            return false;
        }
        files[path].append(data, length);
        return true;
    }
    std::optional<std::size_t> size(const char* path) override {
        auto it = files.find(path);
        if (it == files.end()) {
            return std::nullopt;
        }
        return it->second.size();
    }
    bool rename(const char* from, const char* to) override {
        auto it = files.find(from);
        if (it == files.end()) {
            return false;
        }
        files[to] = it->second;
        files.erase(from);
        return true;
    }
    bool remove(const char* path) override { return files.erase(path) > 0; }

    std::map<std::string, std::string> files;
    bool fail_writes = false;
};

DetectionEvent sample_event(std::uint64_t at) {
    DetectionEvent e;
    e.rule_id = 4;
    e.rule_name = "evil-twin";
    e.severity = Severity::High;
    e.confidence = 85;
    e.timestamp_ms = at;
    e.bssid = testing::kAccessPoint;
    e.explanation = "test";
    return e;
}

EventLogConfig small(const char* dir = "/sd") {
    EventLogConfig c;
    c.directory = dir;
    c.max_bytes = 1024;
    c.keep = 2;
    return c;
}

} // namespace

TEST(log_writes_json_lines) {
    MemoryFs fs;
    EventLog log(fs, small());
    CHECK(log.write_boot(7, "0.1.0", "esp32"));
    CHECK(log.write_event(sample_event(1234)));
    const std::string& f = fs.files["/sd/inapp.log"];
    CHECK(f.find("{\"type\":\"boot\",\"boot\":7,\"version\":\"0.1.0\",\"target\":\"esp32\"}\n") ==
          0);
    CHECK(f.find("{\"type\":\"event\",\"t_ms\":1234,\"rule\":\"evil-twin\"") != std::string::npos);
    CHECK(f.back() == '\n');
    CHECK_EQ(log.stats().lines, 2U);
    CHECK_EQ(log.stats().bytes, f.size());
}

TEST(log_rotates_and_keeps_n_old_files) {
    MemoryFs fs;
    EventLog log(fs, small());
    for (std::uint64_t i = 0; i < 100; ++i) {
        CHECK(log.write_event(sample_event(i)));
    }
    CHECK(fs.files.count("/sd/inapp.log") == 1);
    CHECK(fs.files.count("/sd/inapp1.log") == 1);
    CHECK(fs.files.count("/sd/inapp2.log") == 1);
    CHECK(fs.files.count("/sd/inapp3.log") == 0);
    for (const auto& [name, data] : fs.files) {
        CHECK(data.size() <= 1024);
        CHECK(data.back() == '\n'); // lines never split across files
    }
    CHECK(log.stats().rotations > 2);
    // Newest event is in the current file.
    CHECK(fs.files["/sd/inapp.log"].find("\"t_ms\":99,") != std::string::npos);
}

TEST(log_keep_zero_truncates) {
    MemoryFs fs;
    EventLogConfig c = small();
    c.keep = 0;
    EventLog log(fs, c);
    for (std::uint64_t i = 0; i < 50; ++i) {
        log.write_event(sample_event(i));
    }
    CHECK_EQ(fs.files.size(), 1U);
    CHECK(fs.files["/sd/inapp.log"].size() <= 1024);
}

TEST(log_continues_existing_file_size) {
    MemoryFs fs;
    fs.files["/sd/inapp.log"] = std::string(1000, 'x');
    EventLog log(fs, small());
    log.write_event(sample_event(1)); // would push it past 1024 -> rotates first
    CHECK_EQ(fs.files["/sd/inapp1.log"].size(), 1000U);
    CHECK(fs.files["/sd/inapp.log"].find("\"t_ms\":1,") != std::string::npos);
}

TEST(log_counts_failures_and_recovers) {
    MemoryFs fs;
    EventLog log(fs, small());
    fs.fail_writes = true;
    CHECK(!log.write_event(sample_event(1)));
    CHECK_EQ(log.stats().failures, 1U);
    fs.fail_writes = false; // card reinserted
    CHECK(log.write_event(sample_event(2)));
    CHECK_EQ(log.stats().lines, 1U);
}

TEST(log_status_line) {
    MemoryFs fs;
    EventLog log(fs, small());
    DetectorStats stats;
    stats.observations = 42;
    serial::Status s;
    s.uptime_ms = 5000;
    s.stats = &stats;
    CHECK(log.write_status(s));
    CHECK(fs.files["/sd/inapp.log"].find("{\"type\":\"status\",\"uptime_ms\":5000,\"frames\":42") ==
          0);
}

TEST(log_invalid_config) {
    MemoryFs fs;
    EventLogConfig c;
    c.name = "far-too-long-name";
    CHECK(EventLog(fs, c).config_rejected());
    c = EventLogConfig{};
    c.max_bytes = 10;
    CHECK(EventLog(fs, c).config_rejected());
    c = EventLogConfig{};
    c.keep = 20;
    CHECK(EventLog(fs, c).config_rejected());
}

TEST(log_on_real_files) {
    char dir[] = "/tmp/inapp-test-XXXXXX";
    CHECK(mkdtemp(dir) != nullptr);
    StdioFileSystem fs;
    EventLog log(fs, small(dir));
    for (std::uint64_t i = 0; i < 60; ++i) {
        CHECK(log.write_event(sample_event(i)));
    }
    char path[96];
    for (std::uint8_t i = 0; i <= 2; ++i) {
        log.path(i, path, sizeof path);
        auto size = fs.size(path);
        CHECK(size.has_value() && *size > 0 && *size <= 1024);
        fs.remove(path);
    }
    log.path(3, path, sizeof path);
    CHECK(!fs.size(path));
    CHECK(!fs.rename("/nonexistent/a", "/nonexistent/b"));
    rmdir(dir);
}

TEST(fanout_reaches_every_output) {
    testing::CollectingSink a;
    testing::CollectingSink b;
    EventFanout fanout;
    CHECK(fanout.add(a) && fanout.add(b));
    fanout.emit(sample_event(1));
    CHECK_EQ(a.events.size(), 1U);
    CHECK_EQ(b.events.size(), 1U);
    testing::CollectingSink c;
    testing::CollectingSink d;
    testing::CollectingSink e;
    CHECK(fanout.add(c) && fanout.add(d));
    CHECK(!fanout.add(e));
}
