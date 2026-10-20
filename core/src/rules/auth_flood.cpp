#include "inapparency/rules/auth_flood.hpp"

#include <algorithm>

namespace inapparency::rules {
namespace {

constexpr RuleInfo kInfo{
    AuthFloodRule::kId,
    "auth-flood",
    Severity::Medium,
    "Many join attempts against one access point from many addresses in a short time.",
};

constexpr std::uint32_t kMaxWindowMs = 10U * 60U * 1000U;

constexpr int kBaseConfidence = 40;
constexpr int kMaxVolumeBonus = 20;
constexpr int kManySourcesBonus = 10; // the source table filled up
constexpr int kRandomizedBonus = 5;   // phones randomize too, so it's weak
constexpr int kPartialCoveragePenalty = 5;

constexpr const char* kExplanation =
    "Lots of authentication/association requests to this access point from many different "
    "addresses. Typical of a flood meant to fill its client table. A crowd joining at once "
    "(class change, event start) can look similar.";

bool is_join_request(const ParsedFrame& frame) {
    if (frame.is_management(ManagementSubtype::AssociationRequest) ||
        frame.is_management(ManagementSubtype::ReassociationRequest)) {
        return true;
    }
    // Only the client's half of the handshake. Odd sequence numbers come
    // from the client (1 for open system, 1 and 3 for SAE).
    return frame.is_management(ManagementSubtype::Authentication) &&
           frame.management.auth_sequence && (*frame.management.auth_sequence % 2) == 1;
}

} // namespace

bool AuthFloodConfig::valid() const {
    return threshold > 0 && window_ms >= 20 && window_ms <= kMaxWindowMs && min_sources > 0 &&
           min_sources <= AuthFloodRule::kTrackedSources && min_threshold > 0 &&
           min_threshold <= threshold;
}

AuthFloodRule::AuthFloodRule(const AuthFloodConfig& config) : config_(config) {
    if (!config_.valid()) {
        config_ = AuthFloodConfig{};
        config_rejected_ = true;
    }
}

const RuleInfo& AuthFloodRule::info() const {
    return kInfo;
}

std::uint32_t AuthFloodRule::note_source(State& state, const MacAddress& source,
                                         std::uint64_t now_ms) const {
    const std::uint64_t cutoff = now_ms > config_.window_ms ? now_ms - config_.window_ms : 0;
    std::size_t slot = kTrackedSources;
    std::size_t oldest = 0;
    for (std::size_t i = 0; i < kTrackedSources; ++i) {
        if (state.source_used[i] && state.sources[i] == source) {
            slot = i;
            break;
        }
        if (slot == kTrackedSources && !state.source_used[i]) {
            slot = i;
        }
        if (state.source_seen_ms[i] < state.source_seen_ms[oldest]) {
            oldest = i;
        }
    }
    if (slot == kTrackedSources) {
        slot = oldest;
    }
    state.sources[slot] = source;
    state.source_used[slot] = true;
    state.source_seen_ms[slot] = std::max(state.source_seen_ms[slot], now_ms);

    std::uint32_t distinct = 0;
    for (std::size_t i = 0; i < kTrackedSources; ++i) {
        if (state.source_used[i] && state.source_seen_ms[i] >= cutoff) {
            ++distinct;
        }
    }
    return distinct;
}

void AuthFloodRule::evaluate(const Observation& observation, const ParseResult& result,
                             const DetectionContext& context, EventSink& sink) {
    if (!result.ok() || result.frame.control.protected_frame || !is_join_request(result.frame)) {
        return;
    }
    const ParsedFrame& frame = result.frame;
    const std::uint64_t now = observation.timestamp_ms;

    bool inserted = false;
    State& state = networks_.touch(frame.bssid(), now, inserted);
    if (inserted) {
        state.requests.configure(config_.window_ms);
        state.randomized.configure(config_.window_ms);
    }
    state.requests.add(now);
    if (frame.transmitter().is_locally_administered()) {
        state.randomized.add(now);
    }
    const std::uint32_t distinct = note_source(state, frame.transmitter(), now);

    const std::uint8_t coverage = context.coverage(observation.channel);
    std::uint32_t threshold = config_.threshold;
    std::uint32_t min_sources = config_.min_sources;
    if (coverage < 100) {
        threshold = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(config_.threshold) * coverage + 99) / 100);
        threshold = std::max(threshold, config_.min_threshold);
        min_sources = std::max<std::uint32_t>(
            3, static_cast<std::uint32_t>(
                   (static_cast<std::uint64_t>(config_.min_sources) * coverage + 99) / 100));
    }

    const std::uint32_t count = state.requests.total(now);
    if (count < threshold || distinct < min_sources) {
        return;
    }
    if (state.has_fired && now < state.quiet_until_ms) {
        return;
    }

    int confidence = kBaseConfidence;
    std::uint64_t extra = static_cast<std::uint64_t>(count - threshold) * 10U / threshold;
    confidence += static_cast<int>(std::min<std::uint64_t>(kMaxVolumeBonus, extra));
    if (distinct >= kTrackedSources) {
        confidence += kManySourcesBonus;
    }
    if (static_cast<std::uint64_t>(state.randomized.total(now)) * 10 >=
        static_cast<std::uint64_t>(count) * 9) {
        confidence += kRandomizedBonus;
    }
    if (coverage < 100) {
        confidence -= kPartialCoveragePenalty;
    }
    confidence = std::clamp(confidence, 5, 95);

    DetectionEvent event;
    event.rule_id = kInfo.id;
    event.rule_name = kInfo.name;
    event.timestamp_ms = now;
    event.window_ms = config_.window_ms;
    event.severity = kInfo.severity;
    event.confidence = static_cast<std::uint8_t>(confidence);
    event.evidence_count = count;
    event.bssid = frame.bssid();
    event.channel = observation.channel;
    event.explanation = kExplanation;
    if (coverage < 100) {
        event.coverage_percent = coverage;
    }

    state.has_fired = true;
    state.quiet_until_ms = now + config_.cooldown_ms;
    sink.emit(event);
}

} // namespace inapparency::rules
