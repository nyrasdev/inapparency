#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace inapparency {

// Counts things that happened in the last window_ms using a fixed ring of
// time buckets, so memory stays the same no matter how fast frames arrive.
//
// Accuracy is one bucket: with 20 buckets over 5 s, edges are fuzzy by 250 ms.
// Timestamps that go backwards are counted in their own bucket if it's still
// inside the window, and dropped otherwise.
template <std::size_t Buckets> class RollingCounter {
    static_assert(Buckets > 0);

public:
    RollingCounter() = default;
    explicit RollingCounter(std::uint32_t window_ms) { configure(window_ms); }

    void configure(std::uint32_t window_ms) {
        bucket_ms_ = window_ms / static_cast<std::uint32_t>(Buckets);
        if (bucket_ms_ == 0) {
            bucket_ms_ = 1;
        }
        reset();
    }

    void reset() {
        counts_.fill(0);
        head_ = 0;
        started_ = false;
    }

    std::uint32_t window_ms() const { return bucket_ms_ * static_cast<std::uint32_t>(Buckets); }

    // Returns false when the timestamp is already outside the window.
    bool add(std::uint64_t timestamp_ms, std::uint32_t amount = 1) {
        std::uint64_t bucket = timestamp_ms / bucket_ms_;
        advance(bucket);
        if (bucket + Buckets <= head_) {
            return false;
        }
        std::uint32_t& slot = counts_[bucket % Buckets];
        constexpr auto max = std::numeric_limits<std::uint32_t>::max();
        slot = (max - slot < amount) ? max : slot + amount;
        return true;
    }

    std::uint32_t total(std::uint64_t now_ms) {
        advance(now_ms / bucket_ms_);
        std::uint64_t sum = 0;
        for (auto c : counts_) {
            sum += c;
        }
        constexpr auto max = std::numeric_limits<std::uint32_t>::max();
        return sum > max ? max : static_cast<std::uint32_t>(sum);
    }

private:
    void advance(std::uint64_t bucket) {
        if (!started_) {
            head_ = bucket;
            started_ = true;
            return;
        }
        if (bucket <= head_) {
            return;
        }
        std::uint64_t steps = bucket - head_;
        if (steps >= Buckets) {
            counts_.fill(0);
        } else {
            for (std::uint64_t i = 1; i <= steps; ++i) {
                counts_[(head_ + i) % Buckets] = 0;
            }
        }
        head_ = bucket;
    }

    std::uint32_t bucket_ms_ = 1;
    std::array<std::uint32_t, Buckets> counts_{};
    std::uint64_t head_ = 0;
    bool started_ = false;
};

} // namespace inapparency
