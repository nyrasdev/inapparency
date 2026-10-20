#include "inapparency/rules/ap_change.hpp"

#include <algorithm>

namespace inapparency::rules {
namespace {

constexpr RuleInfo kInfo{
    ApChangeRule::kId,
    "ap-change",
    Severity::Medium,
    "A known access point started beaconing a different name, channel, timing or security.",
};

constexpr const char* kDowngradeAlternating =
    "Same BSSID is beaconing two setups, one with weaker security. Something is likely "
    "impersonating this access point.";
constexpr const char* kDowngradeReplaced =
    "This access point now advertises weaker security than before. Could be a "
    "reconfiguration, or an impersonator that took its place.";
constexpr const char* kChangeAlternating =
    "Same BSSID is beaconing two different setups (name, channel or timing). Possibly a "
    "spoofed access point.";
constexpr const char* kChangeReplaced =
    "This access point changed its name, channel or beacon timing. Usually a normal "
    "reconfiguration.";

BeaconFingerprint fingerprint(const ManagementInfo& info, const SecurityProfile& security) {
    BeaconFingerprint fp;
    if (info.ssid && !info.ssid->is_hidden()) {
        fp.ssid = info.ssid;
    }
    fp.channel = info.ds_channel;
    fp.beacon_interval = info.beacon_interval.value_or(0);
    fp.security = security;
    return fp;
}

} // namespace

bool ApChangeConfig::valid() const {
    return confirmations > 0 && confirmations <= 100 && threshold > 0 && window_ms >= 10 &&
           window_ms <= 10U * 60U * 1000U && settle_ms < window_ms;
}

ApChangeRule::ApChangeRule(const ApChangeConfig& config) : config_(config) {
    if (!config_.valid()) {
        config_ = ApChangeConfig{};
        config_rejected_ = true;
    }
}

const RuleInfo& ApChangeRule::info() const {
    return kInfo;
}

void ApChangeRule::evaluate(const Observation& observation, const ParseResult& result,
                            const DetectionContext& /*context*/, EventSink& sink) {
    if (!result.ok() || !result.frame.is_management(ManagementSubtype::Beacon)) {
        return;
    }
    const ParsedFrame& frame = result.frame;
    auto security = security_profile(frame.management);
    if (!security) {
        return;
    }
    const BeaconFingerprint fp = fingerprint(frame.management, *security);
    const std::uint64_t now = observation.timestamp_ms;

    bool inserted = false;
    State& state = networks_.touch(frame.bssid(), now, inserted);
    if (inserted) {
        state.mismatches.configure(config_.window_ms);
    }

    if (!state.established) {
        if (state.confirmations > 0 && fp == state.baseline) {
            ++state.confirmations;
        } else {
            state.baseline = fp;
            state.confirmations = 1;
        }
        if (state.confirmations >= config_.confirmations) {
            state.established = true;
            state.baseline_seen_ms = now;
        }
        return;
    }

    if (fp == state.baseline) {
        state.baseline_seen_ms = std::max(state.baseline_seen_ms, now);
        return;
    }

    if (state.mismatches.total(now) == 0) {
        state.first_mismatch_ms = now; // a new episode starts
    }
    state.mismatches.add(now);
    const std::uint32_t count = state.mismatches.total(now);
    if (count < config_.threshold) {
        return;
    }
    if (state.has_fired && now < state.quiet_until_ms) {
        return;
    }

    // Alternating: the old setup showed up again after the new one appeared.
    const bool alternating = state.baseline_seen_ms > state.first_mismatch_ms;
    const bool settled =
        now >= state.first_mismatch_ms && now - state.first_mismatch_ms >= config_.settle_ms;
    if (!alternating && !settled) {
        return; // too early to tell a switch-over from a spoof
    }

    const BeaconFingerprint& old = state.baseline;
    const bool downgrade = fp.security.weaker_than(old.security);

    DetectionEvent event;
    event.rule_id = kInfo.id;
    event.rule_name = kInfo.name;
    event.timestamp_ms = now;
    event.window_ms = config_.window_ms;
    event.evidence_count = count;
    event.bssid = frame.bssid();
    event.source = frame.transmitter();
    event.channel = observation.channel;

    int confidence = 0;
    if (downgrade) {
        event.severity = Severity::High;
        confidence = alternating ? 80 : 55;
        event.explanation = alternating ? kDowngradeAlternating : kDowngradeReplaced;
    } else if (alternating) {
        event.severity = Severity::Medium;
        confidence = 50;
        event.explanation = kChangeAlternating;
    } else {
        event.severity = Severity::Info;
        confidence = 15;
        event.explanation = kChangeReplaced;
    }
    event.confidence = static_cast<std::uint8_t>(confidence);

    // A clean switch-over is accepted as the new normal so it isn't reported
    // again and again. If both setups are still on the air, keep the old one.
    if (!alternating) {
        state.baseline = fp;
        state.baseline_seen_ms = now;
        state.mismatches.reset();
    }
    state.has_fired = true;
    state.quiet_until_ms = now + config_.cooldown_ms;
    sink.emit(event);
}

} // namespace inapparency::rules
