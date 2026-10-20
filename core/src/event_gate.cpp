#include "inapparency/event_gate.hpp"

namespace inapparency {
namespace {
constexpr std::uint64_t kMilli = 1000;
constexpr std::uint64_t kMinuteMs = 60'000;
} // namespace

bool EventGateConfig::valid() const {
    return max_per_minute > 0 && max_per_minute <= 6000 && burst > 0 && burst <= 1000 &&
           dedup_ms <= 60U * 60U * 1000U;
}

EventGate::EventGate(EventSink& out, const EventGateConfig& config) : out_(out), config_(config) {
    if (!config_.valid()) {
        config_ = EventGateConfig{};
        config_rejected_ = true;
    }
    tokens_milli_ = static_cast<std::uint64_t>(config_.burst) * kMilli;
}

bool EventGate::is_duplicate(const DetectionEvent& event) {
    const std::uint64_t now = event.timestamp_ms;
    Recent* slot = nullptr;

    for (auto& r : recent_) {
        if (r.used && r.rule_id == event.rule_id && r.bssid == event.bssid) {
            if (now >= r.at_ms && now - r.at_ms < config_.dedup_ms) {
                return true;
            }
            if (now < r.at_ms) {
                return true; // clock went backwards: still the same alert
            }
            slot = &r;
            break;
        }
    }

    if (slot == nullptr) {
        for (auto& r : recent_) {
            if (!r.used) {
                slot = &r;
                break;
            }
            if (slot == nullptr || r.at_ms < slot->at_ms) {
                slot = &r;
            }
        }
    }
    slot->used = true;
    slot->rule_id = event.rule_id;
    slot->bssid = event.bssid;
    slot->at_ms = now;
    return false;
}

bool EventGate::take_token(std::uint64_t now_ms) {
    const std::uint64_t cap = static_cast<std::uint64_t>(config_.burst) * kMilli;
    if (!started_) {
        started_ = true;
        last_refill_ms_ = now_ms;
    } else if (now_ms > last_refill_ms_) {
        std::uint64_t elapsed = now_ms - last_refill_ms_;
        // Cap elapsed so the multiplication can't overflow after long gaps.
        if (elapsed > kMinuteMs * 60) {
            elapsed = kMinuteMs * 60;
        }
        // Carry the leftover between calls so rounding never loses tokens.
        std::uint64_t numerator = elapsed * config_.max_per_minute * kMilli + refill_remainder_;
        std::uint64_t refill = numerator / kMinuteMs;
        refill_remainder_ = numerator % kMinuteMs;
        tokens_milli_ = tokens_milli_ + refill > cap ? cap : tokens_milli_ + refill;
        if (tokens_milli_ == cap) {
            refill_remainder_ = 0;
        }
        last_refill_ms_ = now_ms;
    }
    if (tokens_milli_ < kMilli) {
        return false;
    }
    tokens_milli_ -= kMilli;
    return true;
}

void EventGate::emit(const DetectionEvent& event) {
    if (is_duplicate(event)) {
        ++stats_.duplicates;
        return;
    }
    if (!take_token(event.timestamp_ms)) {
        ++stats_.rate_limited;
        return;
    }
    ++stats_.passed;
    out_.emit(event);
}

} // namespace inapparency
