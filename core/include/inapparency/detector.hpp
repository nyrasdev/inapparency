#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "inapparency/context.hpp"
#include "inapparency/rule.hpp"

namespace inapparency {

struct DetectorStats {
    std::uint64_t observations = 0;
    std::uint64_t ok = 0;
    std::uint64_t empty = 0;
    std::uint64_t truncated = 0;
    std::uint64_t bad_version = 0;
    std::uint64_t unsupported = 0;
    std::uint64_t capture_truncated = 0;
    std::uint64_t events = 0;
};

// Runs the pipeline: parse, learn about networks, hand the frame to every
// enabled rule. The detector doesn't own the rules, so they can live in
// static storage on the device.
class Detector {
public:
    static constexpr std::size_t kMaxRules = 8;

    // Returns false when there's no room or a rule with that id is already in.
    bool add_rule(Rule& rule);

    // Returns false when no rule has that id.
    bool set_rule_enabled(std::uint32_t rule_id, bool enabled);
    bool rule_enabled(std::uint32_t rule_id) const;

    void process(const Observation& observation, EventSink& sink);

    // See DetectionContext::coverage(). Set before frames start arriving.
    void set_channel_coverage(std::uint8_t channel, std::uint8_t percent) {
        context_.set_coverage(channel, percent);
    }

    const DetectorStats& stats() const { return stats_; }
    const DetectionContext& context() const { return context_; }

private:
    struct Slot {
        Rule* rule = nullptr;
        bool enabled = true;
    };

    std::array<Slot, kMaxRules> rules_{};
    std::size_t rule_count_ = 0;
    DetectionContext context_;
    DetectorStats stats_;
};

} // namespace inapparency
