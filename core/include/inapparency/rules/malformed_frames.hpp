#pragma once

#include <cstdint>

#include "inapparency/rolling_counter.hpp"
#include "inapparency/rule.hpp"

namespace inapparency::rules {

struct MalformedFramesConfig {
    std::uint32_t window_ms = 10000;
    std::uint32_t threshold = 10;
    std::uint32_t cooldown_ms = 60000;

    bool valid() const;
};

// Flags a flood of structurally broken management frames.
//
// Counted per channel-wide window instead of per address, since addresses in
// a broken frame can't be trusted. Frames that were only cut off by the
// capture itself don't count.
class MalformedFramesRule final : public Rule {
public:
    static constexpr std::uint32_t kId = 2;

    explicit MalformedFramesRule(const MalformedFramesConfig& config = {});

    const RuleInfo& info() const override;
    void evaluate(const Observation& observation, const ParseResult& result,
                  const DetectionContext& context, EventSink& sink) override;

    const MalformedFramesConfig& config() const { return config_; }
    bool config_rejected() const { return config_rejected_; }

    // True if this observation would count as malformed.
    static bool is_malformed(const Observation& observation, const ParseResult& result);

private:
    MalformedFramesConfig config_;
    bool config_rejected_ = false;
    RollingCounter<20> counter_;
    std::uint64_t quiet_until_ms_ = 0;
    bool has_fired_ = false;
};

} // namespace inapparency::rules
