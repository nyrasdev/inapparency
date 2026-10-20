#include "inapparency/security.hpp"

namespace inapparency {
namespace {
constexpr std::uint16_t kCapabilityPrivacy = 0x0010;
} // namespace

const char* to_string(SecurityProfile::Rank rank) {
    switch (rank) {
    case SecurityProfile::Open:
        return "open";
    case SecurityProfile::Legacy:
        return "WEP/WPA1";
    case SecurityProfile::Wpa2:
        return "WPA2";
    case SecurityProfile::PmfOptional:
        return "WPA2/3 with optional PMF";
    case SecurityProfile::PmfRequired:
        return "PMF required";
    }
    return "unknown";
}

std::optional<SecurityProfile> security_profile(const ManagementInfo& info) {
    if (!info.capability_info) {
        return std::nullopt;
    }
    SecurityProfile profile;
    if (info.rsn) {
        profile.akm_suites = info.rsn->akm_suites;
        if (info.rsn->mfp_required) {
            profile.rank = SecurityProfile::PmfRequired;
        } else if (info.rsn->mfp_capable) {
            profile.rank = SecurityProfile::PmfOptional;
        } else {
            profile.rank = SecurityProfile::Wpa2;
        }
    } else if ((*info.capability_info & kCapabilityPrivacy) != 0) {
        profile.rank = SecurityProfile::Legacy;
    }
    return profile;
}

} // namespace inapparency
