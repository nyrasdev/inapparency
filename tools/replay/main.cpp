// inapparency-replay: runs a monitor-mode capture through the same detector
// the firmware uses and prints what it finds.
//
//   inapparency-replay [--json] [--fcs] [--no-status] [--no-limit] capture.pcap

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "inapparency/correlator.hpp"
#include "inapparency/default_rules.hpp"
#include "inapparency/detector.hpp"
#include "inapparency/event_gate.hpp"
#include "inapparency/host/pcap.hpp"
#include "inapparency/serial/format.hpp"
#include "inapparency/version.hpp"

namespace {

using namespace inapparency;

class PrintSink final : public EventSink {
public:
    explicit PrintSink(serial::Format format) : format_(format) {}
    void emit(const DetectionEvent& event) override {
        char line[512];
        serial::format_event(event, format_, line, sizeof line);
        std::fputs(line, stdout);
    }

private:
    serial::Format format_;
};

int usage() {
    std::fprintf(stderr,
                 "usage: inapparency-replay [--json] [--fcs] [--no-status] [--no-limit] "
                 "capture.pcap\n"
                 "\n"
                 "  --json       print JSON lines instead of text\n"
                 "  --fcs        frames carry a 4-byte FCS (only for captures without radiotap)\n"
                 "  --no-status  skip the summary line at the end\n"
                 "  --no-limit   print every event (no dedup or rate limit, unlike the board)\n"
                 "  --version    print the version\n");
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    serial::Format format = serial::Format::Text;
    bool assume_fcs = false;
    bool status = true;
    bool limit = true;
    const char* path = nullptr;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::printf("inapparency-replay %s\n", kVersion);
            return 0;
        }
        if (std::strcmp(argv[i], "--json") == 0) {
            format = serial::Format::Json;
        } else if (std::strcmp(argv[i], "--fcs") == 0) {
            assume_fcs = true;
        } else if (std::strcmp(argv[i], "--no-status") == 0) {
            status = false;
        } else if (std::strcmp(argv[i], "--no-limit") == 0) {
            limit = false;
        } else if (argv[i][0] == '-' || path != nullptr) {
            return usage();
        } else {
            path = argv[i];
        }
    }
    if (path == nullptr) {
        return usage();
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::fprintf(stderr, "error: can't open %s\n", path);
        return 2;
    }
    std::vector<std::uint8_t> contents((std::istreambuf_iterator<char>(file)),
                                       std::istreambuf_iterator<char>());

    std::string error;
    auto reader = host::PcapReader::open(std::move(contents), error);
    if (!reader) {
        std::fprintf(stderr, "error: %s: %s\n", path, error.c_str());
        return 2;
    }

    DefaultRules rule_set;
    Detector detector;
    rule_set.attach(detector);
    PrintSink printer(format);
    EventGate gate(printer);
    Correlator correlator(limit ? static_cast<EventSink&>(gate) : printer);
    EventSink& sink = correlator;

    std::uint64_t first_ms = 0;
    std::uint64_t last_ms = 0;
    bool started = false;
    std::uint64_t skipped = 0;

    while (auto packet = reader->next()) {
        auto obs = host::to_observation(*packet, reader->linktype(), assume_fcs);
        if (!obs) {
            ++skipped;
            continue;
        }
        if (!started) {
            first_ms = obs->timestamp_ms;
            started = true;
        }
        // Times relative to the start of the capture read better.
        obs->timestamp_ms = obs->timestamp_ms >= first_ms ? obs->timestamp_ms - first_ms : 0;
        last_ms = obs->timestamp_ms > last_ms ? obs->timestamp_ms : last_ms;
        detector.process(*obs, sink);
    }

    if (status) {
        serial::Status s;
        s.uptime_ms = last_ms;
        s.stats = &detector.stats();
        if (limit) {
            s.suppressed = gate.stats().suppressed();
        }
        char line[512];
        serial::format_status(s, format, line, sizeof line);
        std::fputs(line, stdout);
    }
    if (skipped > 0) {
        std::fprintf(stderr, "note: skipped %llu packets (bad FCS or broken radiotap)\n",
                     static_cast<unsigned long long>(skipped));
    }
    if (reader->truncated()) {
        std::fprintf(stderr, "note: capture file ends mid-packet, stopped there\n");
    }
    return 0;
}
