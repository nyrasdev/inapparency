#include "inapparency/rules/deauth_burst.hpp"

#include <algorithm>

namespace inapparency::rules {
namespace {

constexpr RuleInfo kInfo{
    DeauthBurstRule::kId,
    "deauth-burst",
    Severity::High,
    "Many deauthentication or disassociation frames for one network in a short time.",
};

constexpr std::uint32_t kMaxWindowMs = 10U * 60U * 1000U;

constexpr int kBaseConfidence = 35;
constexpr int kMaxVolumeBonus = 20;
constexpr int kSpreadBonus = 10;
constexpr int kSameReasonBonus = 5;
constexpr int kUnprotectedOnPmfBonus = 25;
constexpr int kMixedOnPmfBonus = 10;
constexpr int kProtectedOnPmfPenalty = 25;
constexpr int kPartialCoveragePenalty = 5;
constexpr int kMinConfidence = 5;
constexpr int kMaxConfidence = 95; // a threshold is never proof

constexpr const char* kUnprotectedOnPmf =
    "Unprotected deauth/disassoc burst on a network that requires PMF. The real access point "
    "would protect these, so they are likely forged.";
constexpr const char* kMixedOnPmf =
    "Deauth/disassoc burst on a network that requires PMF, partly unprotected. The unprotected "
    "frames are likely forged.";
constexpr const char* kProtectedOnPmf =
    "Protected deauth/disassoc burst on a PMF network. These normally come from the real access "
    "point, so this may be ordinary behavior.";
constexpr const char* kPmfOptional =
    "Deauth/disassoc burst on a network where PMF is optional. Clients using PMF ignore forged "
    "frames, other clients may get disconnected.";
constexpr const char* kNoPmf =
    "Deauth/disassoc burst on a network without PMF. Forged and real frames look the same here, "
    "so this could be an attack, a rebooting access point or heavy roaming.";
constexpr const char* kUnknownNetwork =
    "Deauth/disassoc burst for a network whose beacons haven't been seen, so its PMF status is "
    "unknown.";

} // namespace

bool DeauthBurstConfig::valid() const {
    return threshold > 0 && window_ms >= 20 && window_ms <= kMaxWindowMs && min_threshold > 0 &&
           min_threshold <= threshold;
}

DeauthBurstRule::DeauthBurstRule(const DeauthBurstConfig& config) : config_(config) {
    if (!config_.valid()) {
        config_ = DeauthBurstConfig{};
        config_rejected_ = true;
    }
}

const RuleInfo& DeauthBurstRule::info() const {
    return kInfo;
}

void DeauthBurstRule::note_target(BurstState& state, const MacAddress& target,
                                  std::uint64_t now_ms) {
    std::size_t oldest = 0;
    for (std::size_t i = 0; i < kTrackedTargets; ++i) {
        if (state.target_used[i] && state.targets[i] == target) {
            state.target_seen_ms[i] = std::max(state.target_seen_ms[i], now_ms);
            return;
        }
        if (!state.target_used[i]) {
            oldest = i;
            break;
        }
        if (state.target_seen_ms[i] < state.target_seen_ms[oldest]) {
            oldest = i;
        }
    }
    state.targets[oldest] = target;
    state.target_seen_ms[oldest] = now_ms;
    state.target_used[oldest] = true;
}

std::uint32_t DeauthBurstRule::distinct_targets(const BurstState& state,
                                                std::uint64_t now_ms) const {
    std::uint64_t cutoff = now_ms > config_.window_ms ? now_ms - config_.window_ms : 0;
    std::uint32_t n = 0;
    for (std::size_t i = 0; i < kTrackedTargets; ++i) {
        if (state.target_used[i] && state.target_seen_ms[i] >= cutoff) {
            ++n;
        }
    }
    return n;
}

void DeauthBurstRule::evaluate(const Observation& observation, const ParseResult& result,
                               const DetectionContext& context, EventSink& sink) {
    if (!result.ok()) {
        return;
    }
    const ParsedFrame& frame = result.frame;
    if (!frame.is_management(ManagementSubtype::Deauthentication) &&
        !frame.is_management(ManagementSubtype::Disassociation)) {
        return;
    }

    const std::uint64_t now = observation.timestamp_ms;
    bool inserted = false;
    BurstState& state = networks_.touch(frame.bssid(), now, inserted);
    if (inserted) {
        state.all.configure(config_.window_ms);
        state.unprotected.configure(config_.window_ms);
        state.broadcast.configure(config_.window_ms);
    }

    if (state.all.total(now) == 0) {
        state.same_reason_streak = 0;
    }
    state.all.add(now);

    if (!frame.control.protected_frame) {
        state.unprotected.add(now);
        if (frame.management.reason_code) {
            std::uint16_t reason = *frame.management.reason_code;
            if (state.same_reason_streak > 0 && reason == state.last_reason) {
                ++state.same_reason_streak;
            } else {
                state.same_reason_streak = 1;
                state.last_reason = reason;
            }
        }
    }

    if (frame.receiver().is_broadcast()) {
        state.broadcast.add(now);
    } else {
        note_target(state, frame.receiver(), now);
    }
    state.last_transmitter = frame.transmitter();

    const std::uint8_t coverage = context.coverage(observation.channel);
    std::uint32_t threshold = config_.threshold;
    if (coverage < 100) {
        std::uint64_t scaled =
            (static_cast<std::uint64_t>(config_.threshold) * coverage + 99) / 100;
        threshold = static_cast<std::uint32_t>(scaled);
        if (threshold < config_.min_threshold) {
            threshold = config_.min_threshold;
        }
    }

    const std::uint32_t count = state.all.total(now);
    if (count < threshold) {
        return;
    }
    if (state.has_fired && now < state.quiet_until_ms) {
        return;
    }

    const std::uint32_t unprotected = state.unprotected.total(now);
    const std::uint32_t broadcast = state.broadcast.total(now);
    const std::uint32_t targets = distinct_targets(state, now);

    int confidence = kBaseConfidence;
    std::uint64_t extra = static_cast<std::uint64_t>(count - threshold) * 10U / threshold;
    confidence += static_cast<int>(std::min<std::uint64_t>(kMaxVolumeBonus, extra));
    if (broadcast > 0 || targets >= 3) {
        confidence += kSpreadBonus;
    }
    if (state.same_reason_streak >= threshold) {
        confidence += kSameReasonBonus;
    }
    if (coverage < 100) {
        confidence -= kPartialCoveragePenalty;
    }

    const char* explanation = kUnknownNetwork;
    if (const NetworkRecord* network = context.network(frame.bssid())) {
        if (network->pmf_required_seen) {
            if (static_cast<std::uint64_t>(unprotected) * 2 >= count) {
                confidence += kUnprotectedOnPmfBonus;
                explanation = kUnprotectedOnPmf;
            } else if (unprotected == 0) {
                confidence -= kProtectedOnPmfPenalty;
                explanation = kProtectedOnPmf;
            } else {
                confidence += kMixedOnPmfBonus;
                explanation = kMixedOnPmf;
            }
        } else if (network->pmf_capable_seen) {
            explanation = kPmfOptional;
        } else {
            explanation = kNoPmf;
        }
    }
    confidence = std::clamp(confidence, kMinConfidence, kMaxConfidence);

    DetectionEvent event;
    event.rule_id = kInfo.id;
    event.rule_name = kInfo.name;
    event.timestamp_ms = now;
    event.window_ms = config_.window_ms;
    event.severity = kInfo.severity;
    event.confidence = static_cast<std::uint8_t>(confidence);
    event.evidence_count = count;
    event.bssid = frame.bssid();
    event.source = state.last_transmitter;
    event.channel = observation.channel;
    event.explanation = explanation;
    if (coverage < 100) {
        event.coverage_percent = coverage;
    }

    state.has_fired = true;
    state.quiet_until_ms = now + config_.cooldown_ms;
    sink.emit(event);
}

} // namespace inapparency::rules
