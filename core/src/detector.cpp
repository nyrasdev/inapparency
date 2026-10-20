#include "inapparency/detector.hpp"

namespace inapparency {

void DetectionContext::learn(const Observation& observation, const ParseResult& result) {
    if (!result.ok()) {
        return;
    }
    const ParsedFrame& frame = result.frame;
    bool beacon_like = frame.is_management(ManagementSubtype::Beacon) ||
                       frame.is_management(ManagementSubtype::ProbeResponse);
    if (!beacon_like || frame.control.protected_frame) {
        return;
    }

    bool inserted = false;
    NetworkRecord& record = networks_.touch(frame.bssid(), observation.timestamp_ms, inserted);
    if (inserted) {
        record.first_seen_ms = observation.timestamp_ms;
    }
    if (observation.timestamp_ms > record.last_seen_ms) {
        record.last_seen_ms = observation.timestamp_ms;
    }
    if (frame.is_management(ManagementSubtype::Beacon)) {
        ++record.beacons_seen;
    }

    const ManagementInfo& info = frame.management;
    if (info.ssid) {
        record.ssid = info.ssid;
    }
    if (info.ds_channel) {
        record.channel = info.ds_channel;
    } else if (observation.channel) {
        record.channel = observation.channel;
    }
    record.rsn = info.rsn;
    if (info.rsn) {
        record.pmf_required_seen = record.pmf_required_seen || info.rsn->mfp_required;
        record.pmf_capable_seen = record.pmf_capable_seen || info.rsn->mfp_capable;
    }
}

bool Detector::add_rule(Rule& rule) {
    if (rule_count_ == kMaxRules) {
        return false;
    }
    for (std::size_t i = 0; i < rule_count_; ++i) {
        if (rules_[i].rule->info().id == rule.info().id) {
            return false;
        }
    }
    rules_[rule_count_++] = Slot{&rule, true};
    return true;
}

bool Detector::set_rule_enabled(std::uint32_t rule_id, bool enabled) {
    for (std::size_t i = 0; i < rule_count_; ++i) {
        if (rules_[i].rule->info().id == rule_id) {
            rules_[i].enabled = enabled;
            return true;
        }
    }
    return false;
}

bool Detector::rule_enabled(std::uint32_t rule_id) const {
    for (std::size_t i = 0; i < rule_count_; ++i) {
        if (rules_[i].rule->info().id == rule_id) {
            return rules_[i].enabled;
        }
    }
    return false;
}

namespace {

// Counts events on their way to the real sink.
class CountingSink final : public EventSink {
public:
    CountingSink(EventSink& inner, std::uint64_t& counter) : inner_(inner), counter_(counter) {}
    void emit(const DetectionEvent& event) override {
        ++counter_;
        inner_.emit(event);
    }

private:
    EventSink& inner_;
    std::uint64_t& counter_;
};

} // namespace

void Detector::process(const Observation& observation, EventSink& sink) {
    ++stats_.observations;
    ParseResult result = parse_frame(observation);

    switch (result.status) {
    case ParseStatus::Ok:
        ++stats_.ok;
        break;
    case ParseStatus::Empty:
        ++stats_.empty;
        break;
    case ParseStatus::Truncated:
        ++stats_.truncated;
        break;
    case ParseStatus::BadVersion:
        ++stats_.bad_version;
        break;
    case ParseStatus::Unsupported:
        ++stats_.unsupported;
        break;
    }
    if (result.capture_truncated) {
        ++stats_.capture_truncated;
    }

    context_.learn(observation, result);

    CountingSink counting(sink, stats_.events);
    for (std::size_t i = 0; i < rule_count_; ++i) {
        if (rules_[i].enabled) {
            rules_[i].rule->evaluate(observation, result, context_, counting);
        }
    }
}

} // namespace inapparency
