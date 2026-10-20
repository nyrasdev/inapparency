#include "inapparency/rules/malformed_frames.hpp"

#include <algorithm>

namespace inapparency::rules {
namespace {

constexpr RuleInfo kInfo{
    MalformedFramesRule::kId,
    "malformed-frames",
    Severity::Low,
    "Many structurally broken management frames in a short time.",
};

constexpr std::uint32_t kMaxWindowMs = 10U * 60U * 1000U;
constexpr int kBaseConfidence = 30;
constexpr int kMaxVolumeBonus = 30;

constexpr const char* kExplanation =
    "Lots of malformed or invalid frames in a short time. Could be a fuzzing tool, a buggy "
    "device or heavy interference.";

} // namespace

bool MalformedFramesConfig::valid() const {
    return threshold > 0 && window_ms >= 20 && window_ms <= kMaxWindowMs;
}

MalformedFramesRule::MalformedFramesRule(const MalformedFramesConfig& config) : config_(config) {
    if (!config_.valid()) {
        config_ = MalformedFramesConfig{};
        config_rejected_ = true;
    }
    counter_.configure(config_.window_ms);
}

const RuleInfo& MalformedFramesRule::info() const {
    return kInfo;
}

bool MalformedFramesRule::is_malformed(const Observation& observation, const ParseResult& result) {
    // A frame cut off by the capture isn't the sender's fault.
    if (result.capture_truncated) {
        return false;
    }
    switch (result.status) {
    case ParseStatus::Truncated:
    case ParseStatus::BadVersion:
        return true;
    case ParseStatus::Ok:
        // Running off the end only counts when we know the capture was whole.
        return result.frame.management.elements_malformed ||
               (result.frame.management.elements_truncated && observation.original_length);
    case ParseStatus::Empty:
    case ParseStatus::Unsupported:
        return false;
    }
    return false;
}

void MalformedFramesRule::evaluate(const Observation& observation, const ParseResult& result,
                                   const DetectionContext& /*context*/, EventSink& sink) {
    if (!is_malformed(observation, result)) {
        return;
    }
    const std::uint64_t now = observation.timestamp_ms;
    counter_.add(now);
    const std::uint32_t count = counter_.total(now);
    if (count < config_.threshold) {
        return;
    }
    if (has_fired_ && now < quiet_until_ms_) {
        return;
    }

    std::uint64_t extra =
        static_cast<std::uint64_t>(count - config_.threshold) * 10U / config_.threshold;
    int confidence =
        kBaseConfidence + static_cast<int>(std::min<std::uint64_t>(kMaxVolumeBonus, extra));

    DetectionEvent event;
    event.rule_id = kInfo.id;
    event.rule_name = kInfo.name;
    event.timestamp_ms = now;
    event.window_ms = config_.window_ms;
    event.severity = kInfo.severity;
    event.confidence = static_cast<std::uint8_t>(confidence);
    event.evidence_count = count;
    event.channel = observation.channel;
    event.explanation = kExplanation;

    has_fired_ = true;
    quiet_until_ms_ = now + config_.cooldown_ms;
    sink.emit(event);
}

} // namespace inapparency::rules
