#pragma once

#include "inapparency/detector.hpp"
#include "inapparency/rules/ap_change.hpp"
#include "inapparency/rules/auth_flood.hpp"
#include "inapparency/rules/deauth_burst.hpp"
#include "inapparency/rules/evil_twin.hpp"
#include "inapparency/rules/malformed_frames.hpp"

namespace inapparency {

// Every built-in rule with default settings, so the firmware, the replay
// tool and tests all run exactly the same set. Keep it in static storage on
// the device; it's about 25 KB.
struct DefaultRules {
    rules::DeauthBurstRule deauth_burst;
    rules::MalformedFramesRule malformed_frames;
    rules::ApChangeRule ap_change;
    rules::EvilTwinRule evil_twin;
    rules::AuthFloodRule auth_flood;

    // Returns false if the detector had no room.
    bool attach(Detector& detector) {
        return detector.add_rule(deauth_burst) && detector.add_rule(malformed_frames) &&
               detector.add_rule(ap_change) && detector.add_rule(evil_twin) &&
               detector.add_rule(auth_flood);
    }
};

} // namespace inapparency
