#include "inapparency/rules/evil_twin.hpp"

#include <algorithm>

namespace inapparency::rules {
namespace {

constexpr RuleInfo kInfo{
    EvilTwinRule::kId,
    "evil-twin",
    Severity::High,
    "A network name is served by several access points, one with weaker security.",
};

constexpr const char* kNewcomerOpen =
    "A new access point appeared with the same name as a protected network, but open. Classic "
    "evil twin: devices that join it send traffic through whoever runs it.";
constexpr const char* kNewcomerWeaker =
    "A new access point appeared with the same name as this network, but weaker security. "
    "Possibly an evil twin trying to get clients to downgrade.";
constexpr const char* kFromStart =
    "Access points sharing this name offer different security, and both were already on the "
    "air when monitoring started. Could be an evil twin or a mismatched setup.";

constexpr int kNewcomerConfidence = 65;
constexpr int kFromStartConfidence = 35;
constexpr int kOpenBonus = 15; // an open copy of a protected network
constexpr int kGapBonus = 5;   // PMF required -> open/WPA2 is a big jump
constexpr int kOtherChannelBonus = 5;

} // namespace

bool EvilTwinConfig::valid() const {
    return min_beacons > 0 && min_beacons <= 100 && expire_ms >= 1000 &&
           expire_ms <= 60U * 60U * 1000U && newcomer_after_ms <= expire_ms * 10;
}

EvilTwinRule::EvilTwinRule(const EvilTwinConfig& config) : config_(config) {
    if (!config_.valid()) {
        config_ = EvilTwinConfig{};
        config_rejected_ = true;
    }
}

const RuleInfo& EvilTwinRule::info() const {
    return kInfo;
}

EvilTwinRule::Network& EvilTwinRule::find_network(const Ssid& ssid, std::uint64_t now_ms) {
    Network* victim = nullptr;
    for (auto& n : networks_) {
        if (n.used && n.ssid == ssid) {
            n.last_seen_ms = std::max(n.last_seen_ms, now_ms);
            return n;
        }
        if (!n.used) {
            if (victim == nullptr || victim->used) {
                victim = &n;
            }
        } else if (victim == nullptr || (victim->used && n.last_seen_ms < victim->last_seen_ms)) {
            victim = &n;
        }
    }
    if (victim->used) {
        ++evictions_;
    }
    *victim = Network{};
    victim->used = true;
    victim->ssid = ssid;
    victim->first_seen_ms = now_ms;
    victim->last_seen_ms = now_ms;
    return *victim;
}

EvilTwinRule::Member* EvilTwinRule::find_member(Network& network, const MacAddress& bssid,
                                                const SecurityProfile& security,
                                                std::uint64_t now_ms) {
    Member* free_slot = nullptr;
    bool equivalent_tracked = false;
    for (auto& m : network.members) {
        if (m.used && m.bssid == bssid) {
            return &m;
        }
        if (!m.used && free_slot == nullptr) {
            free_slot = &m;
        }
        equivalent_tracked = equivalent_tracked || (m.used && m.security == security);
    }

    Member* slot = free_slot;
    if (slot == nullptr) {
        // Full. Big venues have dozens of BSSIDs with one name; another one
        // with security we already track adds nothing.
        if (equivalent_tracked) {
            return nullptr;
        }
        // Make room by dropping a redundant member (one whose security
        // another member also has), least recently seen first.
        for (auto& m : network.members) {
            bool redundant = false;
            for (const auto& other : network.members) {
                redundant = redundant || (&other != &m && other.security == m.security);
            }
            if (redundant && (slot == nullptr || m.last_seen_ms < slot->last_seen_ms)) {
                slot = &m;
            }
        }
        if (slot == nullptr) {
            // Every member is a different kind of security; drop the oldest.
            for (auto& m : network.members) {
                if (slot == nullptr || m.last_seen_ms < slot->last_seen_ms) {
                    slot = &m;
                }
            }
        }
    }
    *slot = Member{};
    slot->used = true;
    slot->bssid = bssid;
    slot->security = security;
    slot->first_seen_ms = now_ms;
    return slot;
}

void EvilTwinRule::evaluate(const Observation& observation, const ParseResult& result,
                            const DetectionContext& /*context*/, EventSink& sink) {
    if (!result.ok() || !result.frame.is_management(ManagementSubtype::Beacon)) {
        return;
    }
    const ManagementInfo& info = result.frame.management;
    if (!info.ssid || info.ssid->is_hidden()) {
        return;
    }
    auto security = security_profile(info);
    if (!security) {
        return;
    }
    const std::uint64_t now = observation.timestamp_ms;
    const MacAddress& bssid = result.frame.bssid();

    Network& network = find_network(*info.ssid, now);
    Member* found = find_member(network, bssid, *security, now);
    if (found == nullptr) {
        return;
    }
    Member& self = *found;
    ++self.beacons;
    self.last_seen_ms = std::max(self.last_seen_ms, now);
    self.channel = info.ds_channel ? info.ds_channel : observation.channel;
    if (!(self.security == *security)) {
        // Security changed under the same BSSID: that's ap-change's job.
        // Start fresh here so one switch isn't read as two networks.
        self.security = *security;
        self.reported = false;
    }

    // Forget members that went quiet.
    for (auto& m : network.members) {
        if (m.used && now > m.last_seen_ms && now - m.last_seen_ms > config_.expire_ms) {
            m = Member{};
        }
    }
    if (self.beacons < config_.min_beacons) {
        return;
    }

    // Find the strongest established sibling that this BSSID is weaker than.
    const Member* strongest = nullptr;
    for (const auto& m : network.members) {
        if (!m.used || &m == &self || m.beacons < config_.min_beacons) {
            continue;
        }
        if (self.security.weaker_than(m.security) &&
            (strongest == nullptr || strongest->security.weaker_than(m.security))) {
            strongest = &m;
        }
    }
    if (strongest == nullptr) {
        return;
    }
    // The weak one was there long before the strong one: someone added a
    // better access point, nobody downgraded anything.
    if (strongest->first_seen_ms > self.first_seen_ms &&
        strongest->first_seen_ms - self.first_seen_ms >= config_.newcomer_after_ms) {
        return;
    }
    if (self.reported && now < self.quiet_until_ms) {
        return;
    }

    // Newcomer: the weak one showed up well after the strong one was known.
    const bool newcomer =
        self.first_seen_ms > strongest->first_seen_ms &&
        self.first_seen_ms - strongest->first_seen_ms >= config_.newcomer_after_ms;

    int confidence = newcomer ? kNewcomerConfidence : kFromStartConfidence;
    const bool open_copy = self.security.rank == SecurityProfile::Open;
    if (open_copy) {
        confidence += kOpenBonus;
    }
    if (strongest->security.rank == SecurityProfile::PmfRequired &&
        self.security.rank <= SecurityProfile::Wpa2) {
        confidence += kGapBonus;
    }
    if (self.channel && strongest->channel && *self.channel != *strongest->channel) {
        confidence += kOtherChannelBonus;
    }
    confidence = std::min(confidence, 95);

    DetectionEvent event;
    event.rule_id = kInfo.id;
    event.rule_name = kInfo.name;
    event.timestamp_ms = now;
    event.window_ms = config_.expire_ms;
    event.severity = kInfo.severity;
    event.confidence = static_cast<std::uint8_t>(confidence);
    event.evidence_count = self.beacons;
    event.bssid = bssid;
    event.related_bssid = strongest->bssid;
    event.channel = observation.channel;
    event.explanation = !newcomer ? kFromStart : open_copy ? kNewcomerOpen : kNewcomerWeaker;

    self.reported = true;
    self.quiet_until_ms = now + config_.cooldown_ms;
    sink.emit(event);
}

} // namespace inapparency::rules
