#include "inapparency/correlator.hpp"

#include <algorithm>

#include "inapparency/rules/ap_change.hpp"
#include "inapparency/rules/deauth_burst.hpp"
#include "inapparency/rules/evil_twin.hpp"

namespace inapparency {
namespace {

constexpr const char* kChainName = "attack-chain";
constexpr const char* kChainExplanation =
    "Deauth burst against an access point while an impostor of it is on the air. This is how "
    "evil twin attacks usually work: kick clients off the real network so they reconnect to the "
    "fake one.";

constexpr int kChainBonus = 10;

template <typename T, std::size_t N>
T& oldest_slot(std::array<T, N>& slots, std::uint64_t T::*time) {
    T* pick = &slots[0];
    for (auto& s : slots) {
        if (!s.used) {
            return s;
        }
        if (s.*time < pick->*time) {
            pick = &s;
        }
    }
    return *pick;
}

} // namespace

bool CorrelatorConfig::valid() const {
    return window_ms >= 1000 && window_ms <= 60U * 60U * 1000U;
}

Correlator::Correlator(EventSink& out, const CorrelatorConfig& config)
    : out_(out), config_(config) {
    if (!config_.valid()) {
        config_ = CorrelatorConfig{};
        config_rejected_ = true;
    }
}

void Correlator::remember(Kind kind, const MacAddress& target, const DetectionEvent& event) {
    Seen* slot = nullptr;
    for (auto& s : seen_) {
        if (s.used && s.kind == kind && s.target == target) {
            slot = &s;
            break;
        }
    }
    if (slot == nullptr) {
        slot = &oldest_slot(seen_, &Seen::at_ms);
    }
    slot->used = true;
    slot->kind = kind;
    slot->target = target;
    slot->impostor = kind == Kind::Impostor ? event.bssid : std::nullopt;
    slot->confidence = event.confidence;
    slot->at_ms = event.timestamp_ms;
}

void Correlator::emit(const DetectionEvent& event) {
    out_.emit(event);

    // Work out what this event says, and about which real access point.
    Kind kind;
    std::optional<MacAddress> target;
    if (event.rule_id == rules::DeauthBurstRule::kId) {
        kind = Kind::Disruption;
        target = event.bssid;
    } else if (event.rule_id == rules::EvilTwinRule::kId) {
        kind = Kind::Impostor;
        target = event.related_bssid;
    } else if (event.rule_id == rules::ApChangeRule::kId && event.severity >= Severity::Medium) {
        // Only the "two setups on one BSSID" kind, not a plain reconfiguration.
        kind = Kind::Impostor;
        target = event.bssid;
    } else {
        return;
    }
    if (!target) {
        return;
    }
    remember(kind, *target, event);

    const Kind other = kind == Kind::Disruption ? Kind::Impostor : Kind::Disruption;
    const std::uint64_t now = event.timestamp_ms;
    const Seen* match = nullptr;
    for (const auto& s : seen_) {
        if (!s.used || s.kind != other || !(s.target == *target)) {
            continue;
        }
        const std::uint64_t gap = now > s.at_ms ? now - s.at_ms : s.at_ms - now;
        if (gap <= config_.window_ms) {
            match = &s;
            break;
        }
    }
    if (match == nullptr) {
        return;
    }

    for (auto& f : fired_) {
        if (f.used && f.target == *target && now < f.until_ms) {
            return;
        }
    }
    Fired& f = oldest_slot(fired_, &Fired::until_ms);
    f.used = true;
    f.target = *target;
    f.until_ms = now + config_.cooldown_ms;

    DetectionEvent chain;
    chain.rule_id = kChainRuleId;
    chain.rule_name = kChainName;
    chain.timestamp_ms = now;
    chain.window_ms = config_.window_ms;
    chain.severity = Severity::Critical;
    chain.confidence = static_cast<std::uint8_t>(
        std::min(95, std::max<int>(event.confidence, match->confidence) + kChainBonus));
    chain.evidence_count = 2;
    chain.bssid = kind == Kind::Impostor ? event.bssid : match->impostor;
    chain.related_bssid = *target;
    chain.channel = event.channel;
    chain.explanation = kChainExplanation;
    ++chains_;
    out_.emit(chain);
}

} // namespace inapparency
